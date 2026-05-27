output "api_url" {
  value       = "${aws_apigatewayv2_api.intake.api_endpoint}/intake"
  description = "POST /intake endpoint."
}

output "intake_table" {
  value       = aws_dynamodb_table.intake.name
  description = "DynamoDB table holding patient submissions."
}

output "uploads_bucket" {
  value       = aws_s3_bucket.uploads.id
  description = "S3 bucket where intake attachments land."
}

output "lambda_function_name" {
  value = aws_lambda_function.intake.function_name
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "evidence_vault_bucket" {
  value       = module.grc_baseline.evidence_vault_bucket_name
  description = "S3 bucket for signed CI/CD evidence bundles. Use this as the EVIDENCE_VAULT GitHub variable."
}

output "cloudtrail_name" {
  value       = module.grc_baseline.cloudtrail_name
  description = "Baseline CloudTrail management event trail."
}

output "cloudtrail_bucket" {
  value       = module.grc_baseline.cloudtrail_bucket_name
  description = "S3 bucket receiving CloudTrail management event logs."
}
