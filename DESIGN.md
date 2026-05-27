# ACME Health Capstone Design

## Initial Case

ACME Health is a fictional 50-person telehealth company that receives patient intake submissions before a first visit. Patients submit a JSON payload to `POST /intake`; the Lambda function stores the intake record in DynamoDB and stores optional attachments in S3.

The workload is intentionally small, but it contains the surfaces a compliance engineer would normally govern:

- API Gateway as the public API and audit-log boundary
- Lambda as the compute and IAM trust boundary
- DynamoDB as PHI record storage
- S3 as PHI attachment storage
- VPC networking and security groups
- CI/CD as the enforcement and evidence-generation path

The original starter was deliberately non-compliant. The capstone objective is not to rebuild the application. The objective is to wrap the inherited workload with enforceable controls, policy gates, signed evidence, and OSCAL traceability.

## Framework Choice

Primary framework: **HIPAA Security Rule**

HIPAA is the primary framework because the workload processes electronic protected health information. The most relevant HIPAA safeguards for this design are:

- `164.312(a)(1)` access control
- `164.312(a)(2)(iv)` encryption and decryption
- `164.312(b)` audit controls
- `164.312(e)(1)` transmission security
- `164.308(a)(7)` contingency and recoverability

Secondary framework: **SOC 2 Trust Services Criteria**

SOC 2 is used as a secondary assurance lens because ACME Health would need enterprise customer trust evidence in addition to HIPAA alignment. The current mappings are:

- `CC6.1` logical access controls
- `CC6.3` authorization and least privilege
- `CC6.7` transmission security
- `CC7.2` monitoring and detection
- `A1.2` availability, backup, and recovery

HIPAA and SOC 2 do not have official OSCAL catalogs in this project. The OSCAL component cites NIST SP 800-66 Rev. 2 as HIPAA implementation guidance and records SOC 2 mappings as secondary properties.

## Control Architecture

The design uses four layers, matching the CGE-P lab pattern.

1. Terraform baseline

   The `terraform/baseline` module owns shared governance controls:

   - customer-managed KMS key for PHI-bearing resources
   - immutable S3 evidence vault with Object Lock
   - CloudTrail management-event trail
   - baseline outputs used by the root workload module and CI pipeline

2. Workload Terraform

   The root `terraform` module owns the application resources:

   - API Gateway
   - Lambda
   - DynamoDB
   - S3 uploads bucket
   - VPC, subnets, route table, internet gateway, and security group

   The root module consumes baseline outputs rather than defining shared compliance resources directly.

3. Policy as Code

   Rego policies under `policies/` enforce the HIPAA controls in CI. The policies are deliberately resource-specific so decoy resources cannot satisfy a control. For example, versioning must be on `aws_s3_bucket.uploads`, not just any S3 bucket.

4. Evidence and OSCAL

   GitHub Actions generates Terraform plan evidence, runs OPA and Conftest gates, signs the evidence bundle with Cosign, and uploads signed artifacts to the Terraform-managed evidence vault after merge to `main`.

   OSCAL traceability lives in `oscal/components/acme-health-component-definition.json`.

## Implemented Controls

| Area | Implementation | Primary mapping | Secondary mapping |
|---|---|---|---|
| S3 PHI encryption | Uploads bucket uses SSE-KMS with the baseline customer-managed KMS key. | HIPAA `164.312(a)(2)(iv)` | SOC 2 `CC6.1`, `CC6.7` |
| DynamoDB PHI encryption | Intake table configures server-side encryption with the baseline KMS key. | HIPAA `164.312(a)(2)(iv)` | SOC 2 `CC6.1` |
| S3 transmission security | Uploads bucket policy denies `aws:SecureTransport=false`. | HIPAA `164.312(e)(1)` | SOC 2 `CC6.7` |
| PHI recovery | Uploads bucket versioning is enabled. | HIPAA `164.308(a)(7)` | SOC 2 `A1.2` |
| Lambda least privilege | Lambda inline policy is scoped to required DynamoDB, S3, and KMS actions. | HIPAA `164.312(a)(1)` | SOC 2 `CC6.3` |
| API audit logging | API Gateway stage has access logging and throttling configured. | HIPAA `164.312(b)` | SOC 2 `CC7.2` |
| Evidence retention | Evidence vault uses S3 Object Lock, versioning, encryption, public access block, TLS deny, and deletion guard. | HIPAA `164.312(b)`, `164.308(a)(7)` | SOC 2 `CC7.2`, `A1.2` |
| Management-event audit trail | CloudTrail is multi-region, includes global service events, and enables log file validation. | HIPAA `164.312(b)` | SOC 2 `CC7.2` |

## Evidence Design

The evidence vault is created by Terraform rather than assumed to exist manually. It is exposed as the `evidence_vault_bucket` output.

Evidence handling is split into two behaviors:

- Pull requests and manual runs bundle and sign evidence so reviewers can inspect artifacts.
- Pushes to `main` apply Terraform, read the Terraform-managed evidence vault output, and upload signed evidence to S3.

The workflow still supports `vars.EVIDENCE_VAULT` as a fallback. That preserves compatibility if the vault was created before this design update or if a separate evidence account is introduced later.

The evidence bundle includes:

- Terraform plan text
- Terraform plan JSON
- OSCAL component files
- SHA-256 checksum
- Cosign signature bundle
- S3 receipt after upload

## Policy Gate Design

The Rego suite intentionally checks semantics rather than the mere presence of related resources.

- DynamoDB encryption requires `aws_dynamodb_table.intake`, SSE enabled, and a customer-managed KMS reference.
- S3 TLS requires a parsed bucket policy statement with `Effect=Deny` and `aws:SecureTransport=false`.
- S3 versioning must reference `aws_s3_bucket.uploads`.
- API logging fails closed if the stage is missing, logging is absent, or logging is empty.
- IAM least privilege rejects wildcard service actions such as `dynamodb:*` and `s3:*`.

This reduces false positives where a decoy bucket, decoy policy, or incomplete config could otherwise pass the gate.

## Trade-Offs

### HIPAA as Primary, SOC 2 as Secondary

HIPAA is the best primary fit because the data is PHI and the most material risks are encryption, access control, auditability, and transmission security. SOC 2 is still valuable, but it is used as a supporting trust framework rather than the driver of control selection.

### Baseline Module Instead of Inline Controls

Moving shared controls into `terraform/baseline` makes the design closer to the CGE-P lab pattern and makes the boundary clear: workload resources live in the root module, reusable governance resources live in the baseline module.

The trade-off is that Terraform state addresses changed for the KMS key. `moved` blocks were added so existing state can follow the refactor.

### Evidence Vault Uses Object Lock Governance Mode

The evidence vault defaults to Object Lock `GOVERNANCE` mode for 30 days. This is strong enough for a lab and avoids the operational pain of `COMPLIANCE` mode, where retention cannot be bypassed even by privileged administrators.

For production, `COMPLIANCE` mode and longer retention should be considered with legal and audit stakeholders.

### CloudTrail Bucket Uses SSE-S3

The CloudTrail log bucket uses SSE-S3 while the evidence vault uses SSE-KMS. This follows the simpler lab baseline pattern for CloudTrail while still ensuring encryption at rest.

The trade-off is key-custody consistency. If ACME requires customer-managed keys for all audit data, CloudTrail log bucket encryption can be moved to the baseline KMS key or a dedicated logging key.

### Lambda Remains in Public Subnets Temporarily

Lambda is currently configured with public subnets because private-subnet placement previously caused runtime connectivity issues. Lambda ENIs do not receive public IPs, so public-subnet placement is not a complete long-term network design by itself.

The intended future design is:

- Lambda in private subnets
- S3 and DynamoDB gateway endpoints, or NAT where needed
- route-table associations for private subnets
- policy coverage that validates endpoint or NAT availability

This is intentionally deferred so the current work can focus on baseline, evidence, CloudTrail, OSCAL, and policy correctness without reintroducing the runtime issue.

### Automatic Apply on Main

The workflow applies Terraform on pushes to `main`. This matches a simple capstone deployment model and makes evidence generation deterministic.

The trade-off is operational risk. A production design would likely require environment protection rules, manual approval, drift detection, and separate plan/apply identities.

## Current Known Conditions

- Terraform validation passes when run outside the local sandbox. The earlier provider error was caused by provider plugin IPC restrictions, not invalid Terraform.
- The refreshed plan shows live AWS drift: the VPC, internet gateway, and public route table were deleted outside Terraform and would be recreated.
- Lambda private-subnet networking is deferred because it previously broke runtime behavior.
- API authentication is out of scope for this capstone starter, but would be required before a real PHI-facing service.
- CMMC is not claimed as an implemented framework in this submission.

## Open Improvements

- Add Rego policies for CloudTrail and evidence vault Object Lock.
- Add private-subnet Lambda networking with S3 and DynamoDB gateway endpoints.
- Add API authentication and authorization.
- Add operational alerts for CloudTrail delivery failures and API errors.
- Consider dedicated KMS keys for evidence, PHI, and audit logs if key separation is required.
