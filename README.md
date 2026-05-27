# cgep-acme-health

Patient Intake API for Acme Health, governed as a CGE-P compliance engineering capstone.

## What This Is

This repository starts from the deliberately flawed `cgep-app-starter` workload and layers on enforceable governance controls:

- Terraform baseline module for KMS, CloudTrail, and immutable evidence storage
- HIPAA-primary and SOC 2-secondary OPA/Rego policy gates
- GitHub Actions plan, policy, apply, evidence signing, and evidence upload workflow
- OSCAL component definition and HIPAA profile mapping implemented controls to the selected frameworks

The inherited workload is intentionally small: API Gateway, Lambda, DynamoDB, S3, and VPC networking for a patient intake flow.

## Frameworks

Primary framework: HIPAA Security Rule

Secondary framework: SOC 2 Trust Services Criteria

CMMC is retained in the starter reference material for comparison, but this submission claims HIPAA as primary and SOC 2 as secondary.

## Local Commands

Set `AWS_PROFILE` in your shell or pass it to `make`.

```bash
make creds AWS_PROFILE=<your-sandbox-profile>
make deploy AWS_PROFILE=<your-sandbox-profile>
make test AWS_PROFILE=<your-sandbox-profile>
```

Run the policy checks against a fresh Terraform plan:

```bash
scripts/bootstrap-terraform-backend.sh
cd terraform
terraform init -input=false
terraform plan -out=tfplan -no-color
terraform show -json tfplan > plan.json
cd ..
opa test policies/
conftest test --policy policies --namespace compliance.hipaa.s3_kms terraform/plan.json
```

The GitHub Actions workflow runs the full HIPAA gate across all namespaces.

Verify the latest signed evidence object in S3:

```bash
scripts/verify-evidence.sh --vault <evidence-vault-bucket>
```

## Grading Evidence

Submit the repo URL with the final commit SHA from `main`.

Recent passing workflow run: <https://github.com/fdicarlo/cgep-acme-health/actions/runs/26506097199>

Required PR history:

- Green PR: <https://github.com/fdicarlo/cgep-acme-health/pull/1>
- Red PR: <https://github.com/fdicarlo/cgep-acme-health/pull/2>

Signed evidence bundle:

```text
s3://acme-health-intake-evidence-vault-7015c378/runs/26506097199/evidence-26506097199-b19830cf80df1219b377d4c689e51b6b4d8ba0de.tar.gz
```

Verification facts:

- SHA-256: `693df5e2ce2a8c57b410a469f1d477917dceb528e918d9e96ca65b3766de18d1`
- Object Lock mode: `GOVERNANCE`
- Retain until: `2026-06-26T10:42:15.284000+00:00`

## Layout

```text
.
├── .github/workflows/grc-gate.yml
├── DESIGN.md
├── FRAMEWORKS.md
├── GAPS.md
├── Makefile
├── README.md
├── WORKLOAD.md
├── WRITEUP.md
├── oscal/components/
├── oscal/profiles/
├── policies/
├── scripts/
├── terraform/
│   ├── baseline/
│   ├── backend.tf
│   ├── lambda/handler.py
│   ├── main.tf
│   ├── moved.tf
│   ├── outputs.tf
│   └── variables.tf
└── test/intake.sh
```

Generated Terraform plans, plan JSON, local state, and Lambda zip packages are intentionally ignored.
