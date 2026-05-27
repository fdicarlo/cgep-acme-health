# CGE-P Capstone Project – Compliance Engineering for ACME Health

## Project Overview

This capstone project implements a secure cloud-native Patient Intake API for a fictional healthcare provider (ACME Health) using Infrastructure-as-Code (IaC), Compliance-as-Code (CaC), and automated evidence generation.

The objective was not only to deploy infrastructure, but to build a system where security and compliance requirements become enforceable technical controls integrated directly into the deployment lifecycle.

The implementation demonstrates:

- Infrastructure provisioning through Terraform
- HIPAA-aligned controls with selected SOC2 considerations
- Compliance policies implemented through OPA/Rego
- Automated policy enforcement through Conftest
- GitHub Actions CI/CD with OIDC authentication
- Signed evidence generation and storage
- Prevention of non-compliant deployments

---

# Business Scenario

ACME Health requires a cloud-hosted Patient Intake API to process healthcare information.

The solution must:

- Protect sensitive health information (PHI)
- Ensure secure data handling
- Maintain auditability
- produce deployment evidence
- prevent infrastructure drift
- integrate compliance directly into engineering workflows

---

# Framework Selection

## Primary Framework: HIPAA

HIPAA was selected as the primary framework because ACME Health processes healthcare information containing Protected Health Information (PHI).

Relevant HIPAA areas include:

- Access controls
- Encryption requirements
- Audit logging
- Transmission security
- Data integrity protections

Examples:

- HIPAA §164.312(a)(2)(iv)
- HIPAA §164.312(b)
- HIPAA §164.312(e)

---

## Secondary Framework: SOC2

SOC2 controls were used as supporting practices to strengthen operational security.

Relevant Trust Service Criteria include:

- Security
- Availability
- Confidentiality

---

# Architecture

The implemented architecture includes:

### Networking

- Dedicated VPC
- Public and private subnets
- Internet Gateway
- Route tables
- Security groups

### Application Layer

- API Gateway
- Lambda function
- DynamoDB storage
- S3 uploads bucket

### Security Components

- Customer-managed KMS keys
- IAM least privilege policies
- TLS enforcement
- S3 versioning
- API logging
- Evidence vault storage

---

# Security Controls Implemented

## S3 Encryption

Requirement:

Sensitive healthcare information must be encrypted at rest.

Implementation:

- SSE-KMS
- Customer-managed KMS key

Policy:

```rego
deny[msg] {
    bucket_missing_kms
}

Mapped:

HIPAA §164.312(a)(2)(iv)
DynamoDB Encryption

Requirement:

Database records containing patient data require encryption.

Implementation:

Customer-managed KMS key

Mapped:

HIPAA §164.312(a)(2)(iv)
TLS Enforcement

Requirement:

Traffic must be encrypted in transit.

Implementation:

Bucket policy denies insecure transport

Mapped:

HIPAA §164.312(e)
Versioning

Requirement:

Prevent accidental data loss.

Implementation:

S3 versioning enabled

Mapped:

HIPAA integrity protections
Least Privilege IAM

Requirement:

Limit access to required operations only.

Implementation:

Restricted Lambda permissions
Minimal KMS permissions
Explicit resource references

Mapped:

HIPAA access controls
Audit Logging

Requirement:

Maintain audit trails.

Implementation:

API Gateway logging enabled
CloudWatch logs

Mapped:

HIPAA §164.312(b)
Compliance-as-Code Implementation

Compliance requirements were translated into executable policies using:

Open Policy Agent (OPA)
Rego
Conftest

Implemented policy suites:

HIPAA S3 KMS
HIPAA DynamoDB KMS
HIPAA TLS
HIPAA Versioning
HIPAA Least Privilege
HIPAA API Logging
Policy Testing

Unit tests were created for all Rego policies.

Examples:

opa test -v policies/

Results:

PASS: 12/12
Terraform Validation

Terraform plans were converted into JSON:

terraform show -json tfplan > plan.json

Conftest validated infrastructure:

conftest test \
--policy policies \
--namespace compliance.hipaa.s3_kms \
terraform/plan.json
CI/CD Pipeline

GitHub Actions workflow implemented:

Checkout repository
Authenticate through AWS OIDC
Terraform validation
Terraform planning
OPA tests
HIPAA policy validation
Terraform apply (main branch only)
Evidence generation
Cosign signing
Evidence upload
OIDC Authentication

Static AWS credentials were intentionally avoided.

GitHub Actions assumed an AWS role using:

OpenID Connect (OIDC)
short-lived credentials
least persistent secrets

Advantages:

Reduced credential exposure
no secret rotation requirements
improved security posture
Evidence Generation

The pipeline automatically generated:

Terraform plan output
Plan JSON
Evidence archive
SHA256 checksum
Cosign signature bundle
Receipt metadata

Evidence was uploaded to:

S3 Evidence Vault

Evidence structure:

runs/
 └── RUN_ID/
      ├── evidence.tar.gz
      ├── evidence.tar.gz.sha256
      ├── evidence.tar.gz.sig.bundle
      └── receipt.json
Validation of Policy Enforcement

To demonstrate enforcement capability, an intentional non-compliant change was introduced.

Removed:

S3 KMS encryption

Expected result:

Policy violation

Observed result:

FAIL:
uploads bucket must use SSE-KMS with customer-managed key

Repository history therefore demonstrates:

PR #1:

Compliant implementation
Merged successfully

PR #2:

Intentional policy violation
Blocked automatically

This validates that the controls actively prevent non-compliant infrastructure.

Challenges Encountered

Several real-world implementation issues occurred during development:

Terraform provider initialization

Issue:

Missing required provider

Resolution:

terraform init
AWS SecurityHub subscription issues

Issue:

SubscriptionRequiredException

Resolution:

Enabled required service subscriptions.

GCP organization vs project policy permissions

Issue:

Role assignment at incorrect resource level.

Resolution:

Applied permissions at organization scope.

Lambda VPC networking

Issue:

Lambda execution failures caused by missing ENI permissions.

Resolution:

Added:

AWSLambdaVPCAccessExecutionRole
GitHub OIDC permissions

Issue:

Insufficient permissions during Terraform apply.

Resolution:

Expanded deployment role permissions for the lab environment.

AWS VPC quota limits

Issue:

Repeated failed deployments created multiple partially provisioned VPCs.

Resolution:

Manual cleanup of unused VPC resources.

Trade-offs

Several design decisions were made to keep the capstone achievable:

Decision	Trade-off
PowerUserAccess on deployment role	Faster implementation but broader permissions
Public subnet Lambda placement	Reduced networking complexity
Manual VPC cleanup	Simplified quota recovery

For production environments these would be replaced with:

strict least privilege deployment roles
NAT gateways or VPC endpoints
automated cleanup workflows
Key Lessons Learned

This project demonstrated that:

Compliance requirements can be converted into executable controls
Security policies can become deployment gates
Evidence generation can be automated
OIDC reduces credential management risk
Infrastructure and compliance engineering can be integrated into one workflow
Conclusion

The capstone successfully implemented an end-to-end compliance engineering workflow where:

Regulation → Control → Policy → Infrastructure → Pipeline → Evidence

The resulting platform prevents non-compliant deployments while automatically generating signed deployment evidence suitable for auditing and future governance activities.