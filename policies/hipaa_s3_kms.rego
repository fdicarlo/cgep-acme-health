# METADATA
# title: HIPAA 164.312(a)(2)(iv) - S3 uploads bucket must use SSE-KMS
# description: "PHI uploads bucket must use customer-managed KMS encryption."
# custom:
#   framework: hipaa-security-rule
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration using sse_algorithm = aws:kms and a customer-managed KMS key."
package compliance.hipaa.s3_kms

import rego.v1

deny contains msg if {
	bucket := "aws_s3_bucket.uploads"
	not has_kms_encryption(bucket)
	msg := sprintf("[HIPAA 164.312(a)(2)(iv)] %s: uploads bucket must use SSE-KMS with a customer-managed key.", [bucket])
}

has_kms_encryption(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)

	some pr in input.planned_values.root_module.resources
	pr.address == r.address
	some rule in pr.values.rule
	rule.apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])