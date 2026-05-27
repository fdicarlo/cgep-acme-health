output "phi_kms_key_arn" {
  value       = aws_kms_key.phi.arn
  description = "ARN of the customer-managed KMS key for PHI-bearing resources."
}

output "phi_kms_key_id" {
  value       = aws_kms_key.phi.key_id
  description = "Key ID of the customer-managed KMS key for PHI-bearing resources."
}

output "phi_kms_alias_name" {
  value       = aws_kms_alias.phi.name
  description = "Alias name for the PHI customer-managed KMS key."
}

output "evidence_vault_bucket_name" {
  value       = aws_s3_bucket.evidence_vault.id
  description = "S3 bucket name for signed CI/CD evidence bundles."
}

output "evidence_vault_bucket_arn" {
  value       = aws_s3_bucket.evidence_vault.arn
  description = "S3 bucket ARN for signed CI/CD evidence bundles."
}

output "cloudtrail_name" {
  value       = aws_cloudtrail.management.name
  description = "Name of the baseline CloudTrail management event trail."
}

output "cloudtrail_bucket_name" {
  value       = aws_s3_bucket.cloudtrail.id
  description = "S3 bucket name for CloudTrail management event logs."
}
