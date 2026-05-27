#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

trestle init --trestle-root "${WORK_DIR}" --local >/dev/null

mkdir -p \
  "${WORK_DIR}/component-definitions/acme-health-component-definition" \
  "${WORK_DIR}/profiles/acme-health-hipaa-profile"

cp \
  "${ROOT_DIR}/oscal/components/acme-health-component-definition.json" \
  "${WORK_DIR}/component-definitions/acme-health-component-definition/component-definition.json"

cp \
  "${ROOT_DIR}/oscal/profiles/acme-health-hipaa-profile.json" \
  "${WORK_DIR}/profiles/acme-health-hipaa-profile/profile.json"

trestle validate \
  --trestle-root "${WORK_DIR}" \
  -f component-definitions/acme-health-component-definition/component-definition.json

trestle validate \
  --trestle-root "${WORK_DIR}" \
  -f profiles/acme-health-hipaa-profile/profile.json
