# Acme Health Capstone Design

## Primary Framework

HIPAA Security Rule

Secondary framework:

SOC2 Type II

Rationale:

Acme Health processes Protected Health Information (PHI) through a Patient Intake API. HIPAA Security Rule was selected because it directly addresses confidentiality, integrity, and availability requirements for ePHI.

SOC2 Type II is treated as a secondary framework supporting enterprise customer trust and assurance objectives.

## Architectural decisions

Cloud:
- AWS us-east-1

Evidence vault:
- S3 Object Lock (GOVERNANCE mode)

Pipeline:
- Automatic apply on merge to main

Accounts:
- Single account deployment

Control philosophy:

Preventive:
- Terraform baseline
- KMS
- IAM restrictions
- Bucket policies

Detective:
- CloudTrail
- Evidence pipeline
- Policy as Code

Assurance:
- OSCAL
- Signed evidence
- Immutable storage

## Target gaps

- GAP-01
- GAP-02
- GAP-03
- GAP-04
- GAP-05
- GAP-07
- GAP-08