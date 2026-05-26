### OIDC Trust Boundary Troubleshooting

The GitHub Actions pipeline initially failed while attempting to assume the AWS role through OIDC:

Error:
`Not authorized to perform sts:AssumeRoleWithWebIdentity`

Root cause:

The IAM role trust policy permitted only the previously used repository (`cgep-compliance-engineering-labs`) and did not include the new capstone repository (`cgep-acme-health`).

Resolution:

Updated the role trust relationship to allow:

repo:fdicarlo/cgep-acme-health:*

Outcome:

The pipeline successfully obtained short-lived AWS credentials without storing long-lived access keys in GitHub.