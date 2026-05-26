# METADATA
# title: HIPAA 164.312(a)(2)(iv) - DynamoDB must use customer-managed KMS
# custom:
#   framework: hipaa-security-rule
#   controls: ["164.312(a)(2)(iv)"]
#   severity: high
package compliance.hipaa.dynamodb_kms

import rego.v1

deny contains msg if {
	not has_sse_kms
	msg := "[HIPAA 164.312(a)(2)(iv)] aws_dynamodb_table.intake: DynamoDB table must configure server_side_encryption with a customer-managed KMS key."
}

has_sse_kms if {
	some r in input.configuration.root_module.resources
	r.address == "aws_dynamodb_table.intake"
	r.expressions.server_side_encryption
}