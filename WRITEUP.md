# CGE-P Capstone Write-Up: ACME Health Patient Intake

This capstone declares the **HIPAA Security Rule** as the primary framework for Acme Health because the Patient Intake API receives Protected Health Information (PHI). **SOC 2 Trust Services Criteria** are treated as a secondary assurance lens for enterprise customers, but HIPAA drives the Terraform baseline, Rego policy suite, GitHub Actions gate, OSCAL component, and evidence bundle.

## Executive Summary

Acme Health inherited a working Patient Intake API, but the starter system was not audit-defensible. The goal of this project was to keep the application usable while wrapping it in controls that are provisioned, tested, enforced, signed, and stored as evidence automatically.

The result is a single repository that combines:

- Terraform for the workload and GRC baseline
- HIPAA-aligned policy-as-code with OPA/Rego and Conftest
- A GitHub Actions deployment gate using AWS OIDC
- Keyless Cosign signing for evidence bundles
- A Terraform-managed S3 evidence vault with Object Lock
- An OSCAL component definition describing the implemented controls

The design is intentionally small. I focused on closing the most material starter gaps and proving the evidence chain end to end rather than adding a broad set of unrelated security services.

## Business Scenario

Acme Health is a 50-person telehealth company. The engineering team has shipped a Patient Intake API, and the CTO needs the system to become audit-defensible without slowing product delivery.

The system needs to protect PHI, prevent known infrastructure regressions, and produce repeatable evidence that controls remain in place. That is why the implementation treats CI/CD as a control surface: every proposed infrastructure change is planned, tested against policy, and either blocked or applied with signed evidence.

## Framework Choice

HIPAA is the primary framework because the workload stores and processes patient-submitted health information. The most relevant HIPAA Security Rule safeguards for this project are encryption at rest, transmission security, audit controls, access control, and contingency protections.

SOC 2 is secondary because Acme is also pursuing enterprise trust. SOC 2 maps naturally to least privilege, logging, availability, and change governance, but the capstone control IDs, policy messages, and OSCAL implementation are grounded in HIPAA.

CMMC Level 2 is not claimed. Several controls, such as least privilege and transmission security, would support a future CMMC mapping, but this submission does not implement the full CMMC control set.

## Architecture

The starter workload remains the core system: API Gateway receives patient intake submissions, invokes Lambda, stores structured metadata in DynamoDB, and stores uploaded content in S3. The capstone adds a GRC baseline around that workload rather than replacing it.

The Terraform layout separates responsibilities:

- `terraform/main.tf` defines the workload resources and starter gap remediations.
- `terraform/baseline/` defines reusable governance resources: KMS, evidence vault, and CloudTrail.
- `policies/` contains the HIPAA policy suite and unit tests.
- `.github/workflows/grc-gate.yml` runs the integrated plan, policy, apply, sign, and upload flow.
- `oscal/` describes the component and selected HIPAA controls.

## Layer 1: Terraform Baseline

The baseline provisions a customer-managed KMS key with rotation enabled, an Object Lock evidence vault, and a multi-region CloudTrail trail with log-file validation. The workload consumes the KMS key for PHI-bearing resources.

Implemented gap remediation:

| Starter gap | Terraform remediation | HIPAA mapping |
|---|---|---|
| GAP-01: uploads bucket lacks customer CMK custody | `aws_s3_bucket_server_side_encryption_configuration.uploads` uses SSE-KMS with the baseline CMK. | `164.312(a)(2)(iv)` |
| GAP-02: DynamoDB uses AWS-owned/default encryption | `aws_dynamodb_table.intake` enables SSE with the baseline CMK. | `164.312(a)(2)(iv)` |
| GAP-03: uploads bucket lacks TLS deny policy | `aws_s3_bucket_policy.uploads_tls` denies `aws:SecureTransport=false`. | `164.312(e)(1)` |
| GAP-04: uploads bucket lacks versioning | `aws_s3_bucket_versioning.uploads` enables versioning. | `164.308(a)(7)` |
| GAP-05: Lambda is outside the starter VPC | `aws_lambda_function.intake` includes `vpc_config` attached to the starter VPC subnets and Lambda security group. | `164.312(e)(1)` |
| GAP-07: Lambda IAM is overbroad | `aws_iam_role_policy.lambda_inline` scopes DynamoDB, S3, and KMS actions to required operations and resources. | `164.312(a)(1)` |
| GAP-08: API Gateway lacks logging/throttling | `aws_apigatewayv2_stage.default` enables access logging and route throttling. | `164.312(b)` |

The evidence vault is versioned, encrypted with SSE-KMS, protected by public-access blocks, protected by a TLS-deny bucket policy, and configured with Object Lock in `GOVERNANCE` mode for 30 days.

## Layer 2: OPA Policy Suite

The policy suite has six HIPAA policies, each with metadata, tests, failing fixtures, and deny messages that cite the relevant HIPAA control ID:

- `hipaa_s3_kms.rego`
- `hipaa_dynamodb_kms.rego`
- `hipaa_s3_tls.rego`
- `hipaa_s3_versioning.rego`
- `hipaa_iam_least_privilege.rego`
- `hipaa_api_logging.rego`

The policies are not generic tag checks. They target the starter's material gaps: customer-managed encryption, TLS enforcement, versioning, least privilege, and audit logging. Conftest runs these policies against the Terraform plan, so a reintroduced gap blocks the deployment before apply.

## Layer 3: Pipeline And Evidence

The GitHub Actions workflow `.github/workflows/grc-gate.yml` runs one integrated flow:

1. Plan Terraform and emit `terraform/plan.json`.
2. Run OPA unit tests and Conftest HIPAA checks.
3. Apply Terraform on pushes to `main`.
4. Sign the evidence bundle with Cosign keyless signing through GitHub OIDC.
5. Upload the signed bundle, checksum, signature bundle, and receipt to the Terraform-managed evidence vault.

The workflow uses GitHub OIDC to assume an AWS role, avoiding long-lived AWS credentials in repository secrets.

Because this capstone uses a sandbox without durable remote Terraform state, repeated main-branch runs can leave old Acme VPCs behind and exhaust the default five-VPC regional quota in `us-east-1`. To keep the capstone deployable, the workflow runs `scripts/cleanup-acme-vpcs.py` as a pre-flight step before plan/apply on `main`. The script is intentionally scoped to Acme Health VPCs and VPC-scoped dependencies. In production, I would replace this with remote state, state locking, and normal lifecycle management rather than cleanup before deploy.

## Layer 4: OSCAL Component

The OSCAL component definition lives at `oscal/components/acme-health-component-definition.json`. It describes the actual system built in this repository: the starter workload, Terraform hardening controls, policy gate, and evidence pipeline.

The OSCAL layer includes:

- Real UUIDs
- A HIPAA/NIST SP 800-66-oriented control implementation source
- Implementation statements with Terraform addresses and AWS resource references
- Evidence links to signed S3 evidence objects
- A profile at `oscal/profiles/acme-health-hipaa-profile.json` selecting the implemented HIPAA controls

I validated the OSCAL JSON structure locally with `jq`. I did not run full `trestle` validation locally because `trestle` was not installed in the workspace; adding that to CI is one of the follow-up items.

## Evidence Verification

Recent successful evidence run:

- GitHub Actions run: `26506097199`
- Commit: `b19830cf80df1219b377d4c689e51b6b4d8ba0de`
- Evidence vault: `acme-health-intake-evidence-vault-7015c378`
- Bundle: `s3://acme-health-intake-evidence-vault-7015c378/runs/26506097199/evidence-26506097199-b19830cf80df1219b377d4c689e51b6b4d8ba0de.tar.gz`
- Checksum: `s3://acme-health-intake-evidence-vault-7015c378/runs/26506097199/evidence-26506097199-b19830cf80df1219b377d4c689e51b6b4d8ba0de.tar.gz.sha256`
- Signature bundle: `s3://acme-health-intake-evidence-vault-7015c378/runs/26506097199/evidence-26506097199-b19830cf80df1219b377d4c689e51b6b4d8ba0de.tar.gz.sig.bundle`
- Receipt: `s3://acme-health-intake-evidence-vault-7015c378/runs/26506097199/receipt.json`

Verification performed:

- SHA-256 recompute matched: `693df5e2ce2a8c57b410a469f1d477917dceb528e918d9e96ca65b3766de18d1`
- Cosign keyless verification returned `Verified OK`
- S3 object metadata shows `ServerSideEncryption = aws:kms`
- S3 Object Lock retention is active in `GOVERNANCE` mode until `2026-06-26T10:42:15.284000+00:00`

## Gate Evidence

The repository history includes both required PR outcomes:

- Green PR: [#1 HIPAA policy suite and Terraform controls](https://github.com/fdicarlo/cgep-acme-health/pull/1), merged after `grc-gate` succeeded.
- Red PR: [#2 Intentional control failure validation](https://github.com/fdicarlo/cgep-acme-health/pull/2), closed after `grc-gate` failed as expected.

This demonstrates the intended behavior: compliant changes can merge, while a deliberately reintroduced control failure is blocked by policy before apply.

## Design Trade-Offs

**HIPAA primary, SOC 2 secondary.** HIPAA is the better primary framework because PHI is the system's defining risk. SOC 2 remains useful for customer assurance, but treating SOC 2 as primary would make the submission less direct.

**`us-east-1`.** I used `us-east-1` because it was the only region used in the sandbox and it kept CI, evidence verification, and cleanup scope simple.

**Object Lock `GOVERNANCE` mode.** `GOVERNANCE` mode provides immutability while preserving a privileged recovery path for a short capstone environment. In a production evidence account, I would evaluate `COMPLIANCE` mode once retention rules, access model, and recovery procedures are settled.

**Single AWS account.** A separate evidence-vault account would provide stronger separation of duties and blast-radius reduction. For a 30-day capstone, a single account was acceptable and kept the end-to-end path easier to demonstrate.

**Apply on merge to `main`.** I chose automatic apply on `main` because the capstone emphasizes integration: the gate plans, decides, applies, signs, and uploads evidence in one flow. A production environment might add a manual approval or environment protection rule after the policy gate.

**Lambda networking.** Lambda is attached to the starter VPC, satisfying the starter gap. It currently uses public subnets because private-subnet placement previously caused runtime connectivity failures. Lambda ENIs do not receive public IPs, so this is not the final network design I would choose for production. The next iteration should move Lambda to private subnets and add S3/DynamoDB VPC endpoints or NAT for AWS API access.

**API Gateway WAF.** GAP-08 includes logging, throttling, and WAF. This submission implements logging and throttling, and documents WAF as a follow-up. I prioritized controls that directly align with HIPAA auditability and could be reliably enforced in the current HTTP API setup.

## Troubleshooting And Lessons Learned

The most important implementation lesson was that compliance automation still depends on ordinary cloud operations hygiene. Without remote Terraform state, CI can create repeated sandbox stacks and hit AWS service quotas. The VPC cleanup script is a pragmatic capstone guardrail, not a production state strategy.

The Lambda VPC issue was another useful lesson. Moving Lambda into a VPC is not just a Terraform checkbox; private subnet placement also requires a path to AWS APIs. Otherwise a control can pass structurally while the workload fails at runtime. That is why this submission is honest about the current subnet choice and the next-step endpoint/NAT design.

The Rego policies also improved during the project. Initial versions were too permissive because they checked for the presence of resources rather than the exact resource-policy relationship. The final policies bind checks to the relevant bucket/table/stage and verify the intended control behavior.

## What I Would Do With Another Sprint

- Move Lambda into private subnets with S3 and DynamoDB VPC endpoints.
- Add WAF or an equivalent API protection layer if supported by the chosen API Gateway model.
- Add DynamoDB point-in-time recovery and a corresponding policy check.
- Split the evidence vault into a dedicated AWS account.
- Replace pre-flight cleanup with remote Terraform state, locking, and a controlled import/migration path.
- Add a verification script that checks the latest S3 evidence object, SHA-256, Cosign bundle, and Object Lock retention in one command.
- Add `trestle` validation to CI for OSCAL.
- Tighten the GitHub deployment role to the smallest practical Terraform permission set.

## What I Did Not Get To

This submission does not claim full SOC 2 or CMMC implementation. It also does not fully close the WAF portion of GAP-08 or the resilience/observability items in GAP-06, such as reserved concurrency, DLQ, and X-Ray. Those are valuable controls, but I prioritized HIPAA-relevant encryption, transmission security, auditability, least privilege, and evidence custody.

## Submission Checklist Status

| Requirement | Status |
|---|---|
| Repo is a clear derivative of the starter and keeps the workload runnable | Done |
| Primary framework named in `WRITEUP.md` and OSCAL | Done |
| Terraform adds KMS, evidence vault with Object Lock, CloudTrail, and hardening overrides | Done |
| Five or more HIPAA Rego policies with tests | Done |
| Workflow runs Plan, Policy check, Apply, Sign, Upload | Done |
| One green PR and one red PR visible in history | Done |
| Signed evidence bundle in Object Lock vault | Done |
| OSCAL component present | Done; JSON structure checked, full `trestle` validation still recommended |
| README has grader verification instructions | Done |
