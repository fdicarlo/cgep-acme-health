# CGE-P Capstone Write-Up: ACME Health Patient Intake

This capstone declares the **HIPAA Security Rule** as the primary framework for ACME Health because the Patient Intake API processes Protected Health Information (PHI). **SOC 2 Trust Services Criteria** are used as a secondary mapping for customer assurance, but HIPAA drives the Terraform baseline, Rego policy suite, pipeline gate, OSCAL component, and evidence bundle.

## Design Decisions

ACME Health is a small telehealth company with a working Patient Intake API that was not audit-defensible. I kept the starter workload intact and wrapped it with governance controls instead of rebuilding the application. The resulting system uses the starter VPC, API Gateway, Lambda, DynamoDB table, and S3 uploads bucket, then adds a Terraform baseline module for shared controls.

The baseline module owns the governance resources:

- Customer-managed KMS key with rotation enabled
- S3 evidence vault with Object Lock, versioning, SSE-KMS, public access blocking, and TLS denial
- CloudTrail management trail with multi-region logging and log-file validation

The root Terraform module owns the workload resources and consumes baseline outputs. That keeps the boundary clear: application infrastructure remains in the workload module, while reusable compliance controls live in `terraform/baseline`.

## Control Coverage

| Gap | Remediation | HIPAA control | Evidence |
|---|---|---|---|
| S3 uploads encryption | `aws_s3_bucket_server_side_encryption_configuration.uploads` uses SSE-KMS with the baseline CMK. | `164.312(a)(2)(iv)` | `policies/hipaa_s3_kms.rego` |
| DynamoDB encryption | `aws_dynamodb_table.intake` uses customer-managed KMS encryption. | `164.312(a)(2)(iv)` | `policies/hipaa_dynamodb_kms.rego` |
| S3 TLS enforcement | `aws_s3_bucket_policy.uploads_tls` denies non-TLS requests using `aws:SecureTransport=false`. | `164.312(e)(1)` | `policies/hipaa_s3_tls.rego` |
| S3 versioning | `aws_s3_bucket_versioning.uploads` enables object versioning. | `164.308(a)(7)` | `policies/hipaa_s3_versioning.rego` |
| Lambda VPC placement | `aws_lambda_function.intake` has `vpc_config` attached to the starter VPC. | `164.312(e)(1)` | Terraform plan evidence |
| Lambda IAM least privilege | `aws_iam_role_policy.lambda_inline` uses scoped DynamoDB, S3, and KMS actions. | `164.312(a)(1)` | `policies/hipaa_iam_least_privilege.rego` |
| API logging/throttling | `aws_apigatewayv2_stage.default` has access logs and route throttling. | `164.312(b)` | `policies/hipaa_api_logging.rego` |
| Evidence custody | Signed evidence bundles are uploaded to an Object Lock vault. | `164.312(b)` | S3 object retention and Cosign verification |

The policy suite has six HIPAA Rego policies and matching tests. Each policy cites the HIPAA control ID in the deny message and includes metadata for framework, controls, severity, and remediation.

## Pipeline

The GitHub Actions workflow `.github/workflows/grc-gate.yml` runs one integrated flow:

1. Plan Terraform and emit `plan.json`.
2. Run OPA unit tests and Conftest policy checks.
3. Apply Terraform on pushes to `main`.
4. Sign the evidence bundle with Cosign keyless signing through GitHub OIDC.
5. Upload the signed bundle, checksum, signature bundle, and receipt to the Terraform-managed evidence vault.

The workflow uses GitHub OIDC to assume an AWS role, avoiding long-lived AWS credentials in GitHub secrets.

## Evidence

Recent successful evidence run:

- Run: `26498080213`
- Commit: `260df8ee212073e165a536d33ee6b9e633015e7c`
- Bundle: `s3://acme-health-intake-evidence-vault-d2514106/runs/26498080213/evidence-26498080213-260df8ee212073e165a536d33ee6b9e633015e7c.tar.gz`
- Checksum: `s3://acme-health-intake-evidence-vault-d2514106/runs/26498080213/evidence-26498080213-260df8ee212073e165a536d33ee6b9e633015e7c.tar.gz.sha256`
- Signature bundle: `s3://acme-health-intake-evidence-vault-d2514106/runs/26498080213/evidence-26498080213-260df8ee212073e165a536d33ee6b9e633015e7c.tar.gz.sig.bundle`
- Receipt: `s3://acme-health-intake-evidence-vault-d2514106/runs/26498080213/receipt.json`

Verification performed:

- SHA-256 recompute matched: `b6c7b1fb37819565f6bacfbf16d70036e3efdb4d07a18e4030b40b4517307f37`
- Cosign keyless verification returned `Verified OK`
- S3 object metadata shows `ServerSideEncryption = aws:kms`
- S3 Object Lock retention is active in `GOVERNANCE` mode until `2026-06-26T07:51:15.421000+00:00`

## Gate Evidence

The repo history includes both required PR outcomes:

- Green PR: [#1 HIPAA policy suite and Terraform controls](https://github.com/fdicarlo/cgep-acme-health/pull/1), merged after `grc-gate` succeeded.
- Red PR: [#2 Intentional control failure validation](https://github.com/fdicarlo/cgep-acme-health/pull/2), closed with `grc-gate` failing as expected.

This demonstrates that compliant changes can merge while a reintroduced gap is blocked by the policy gate.

## Trade-Offs

The evidence vault uses `GOVERNANCE` mode rather than `COMPLIANCE` mode. For a 30-day capstone, governance mode provides immutable retention while still allowing privileged recovery if a lab mistake locks incorrect objects. In production, I would revisit whether compliance mode is required for audit evidence.

The deployment uses a single AWS account. A separate evidence account would provide stronger separation of duties and blast-radius reduction, but the single-account model keeps the capstone small and integrated.

Lambda remains attached to public subnets because private-subnet placement previously caused runtime connectivity failures. Lambda ENIs do not receive public IPs, so this is not a complete long-term network pattern. A production-ready version should move Lambda to private subnets and add S3/DynamoDB VPC endpoints or NAT for AWS API access.

The GitHub deployment role is broader than a production least-privilege role. For the capstone, the priority was proving the end-to-end control and evidence pipeline. A production sprint should reduce the deployment role to the exact Terraform action set.

## What I Would Do With Another Sprint

- Move Lambda into private subnets with S3 and DynamoDB VPC endpoints.
- Add WAF or an authorizer in front of the public API.
- Add DynamoDB point-in-time recovery.
- Split the evidence vault into a dedicated AWS account.
- Add a script that verifies the latest S3 evidence object, checksum, Cosign bundle, and Object Lock retention in one command.
- Validate OSCAL with `trestle` in CI.

## What I Did Not Get To

This submission does not claim full SOC 2 or CMMC implementation. SOC 2 mappings are present as secondary context, and CMMC remains reference material only. The implemented control set is deliberately focused on HIPAA-relevant starter gaps and on proving an auditable deployment pipeline.
