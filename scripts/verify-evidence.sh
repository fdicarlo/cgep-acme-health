#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/verify-evidence.sh --vault BUCKET [--run-id RUN_ID] [--sha COMMIT_SHA] [--region REGION]

Verifies a signed evidence bundle in S3:
  - locates the latest run prefix when --run-id is omitted
  - downloads the .tar.gz, .sha256, and .sig.bundle files
  - recomputes SHA-256
  - verifies the Sigstore/Cosign bundle against the GitHub Actions OIDC identity
  - checks S3 Object Lock retention for the bundle object
USAGE
}

VAULT=""
RUN_ID=""
SHA=""
REGION="us-east-1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)
      VAULT="$2"
      shift 2
      ;;
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --sha)
      SHA="$2"
      shift 2
      ;;
    --region)
      REGION="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$VAULT" ]]; then
  echo "--vault is required" >&2
  usage >&2
  exit 2
fi

if [[ -z "$RUN_ID" ]]; then
  RUN_ID="$(
    aws s3api list-objects-v2 \
      --bucket "$VAULT" \
      --prefix runs/ \
      --delimiter / \
      --query 'CommonPrefixes[].Prefix' \
      --output text |
      tr '\t' '\n' |
      sed -E 's#^runs/([0-9]+)/$#\1#' |
      sort -V |
      tail -n 1
  )"
fi

if [[ -z "$RUN_ID" ]]; then
  echo "No evidence run prefixes found in s3://${VAULT}/runs/" >&2
  exit 1
fi

PREFIX="runs/${RUN_ID}"
if [[ -z "$SHA" ]]; then
  BUNDLE_KEY="$(
    aws s3api list-objects-v2 \
      --bucket "$VAULT" \
      --prefix "${PREFIX}/evidence-${RUN_ID}-" \
      --query 'Contents[?ends_with(Key, `.tar.gz`)].Key | [0]' \
      --output text
  )"
else
  BUNDLE_KEY="${PREFIX}/evidence-${RUN_ID}-${SHA}.tar.gz"
fi

if [[ -z "$BUNDLE_KEY" || "$BUNDLE_KEY" == "None" ]]; then
  echo "No evidence bundle found under s3://${VAULT}/${PREFIX}/" >&2
  exit 1
fi

BUNDLE="$(basename "$BUNDLE_KEY")"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

aws s3 cp "s3://${VAULT}/${BUNDLE_KEY}" "${WORKDIR}/${BUNDLE}" --region "$REGION" >/dev/null
aws s3 cp "s3://${VAULT}/${BUNDLE_KEY}.sha256" "${WORKDIR}/${BUNDLE}.sha256" --region "$REGION" >/dev/null
aws s3 cp "s3://${VAULT}/${BUNDLE_KEY}.sig.bundle" "${WORKDIR}/${BUNDLE}.sig.bundle" --region "$REGION" >/dev/null

EXPECTED_SHA="$(cat "${WORKDIR}/${BUNDLE}.sha256")"
ACTUAL_SHA="$(shasum -a 256 "${WORKDIR}/${BUNDLE}" | awk '{print $1}')"

if [[ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]]; then
  echo "SHA-256 mismatch: expected ${EXPECTED_SHA}, got ${ACTUAL_SHA}" >&2
  exit 1
fi

cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/fdicarlo/cgep-acme-health/.github/workflows/grc-gate.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle "${WORKDIR}/${BUNDLE}.sig.bundle" \
  "${WORKDIR}/${BUNDLE}" >/dev/null

RETENTION_JSON="$(
  aws s3api get-object-retention \
    --bucket "$VAULT" \
    --key "$BUNDLE_KEY" \
    --region "$REGION" \
    --output json
)"

MODE="$(printf '%s' "$RETENTION_JSON" | jq -r '.Retention.Mode')"
RETAIN_UNTIL="$(printf '%s' "$RETENTION_JSON" | jq -r '.Retention.RetainUntilDate')"

if [[ "$MODE" == "null" || -z "$MODE" ]]; then
  echo "Object Lock retention is not active for s3://${VAULT}/${BUNDLE_KEY}" >&2
  exit 1
fi

cat <<EOF
Evidence verification passed.
Vault: s3://${VAULT}
Run: ${RUN_ID}
Bundle: s3://${VAULT}/${BUNDLE_KEY}
SHA-256: ${ACTUAL_SHA}
Object Lock: ${MODE} until ${RETAIN_UNTIL}
EOF
