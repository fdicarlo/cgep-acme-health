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
	cfg := configured_table
	cfg.expressions.server_side_encryption[0].kms_key_arn.references
	some ref in cfg.expressions.server_side_encryption[0].kms_key_arn.references
	is_customer_managed_key_ref(ref)

	planned := planned_table
	planned.values.server_side_encryption[0].enabled == true
}

configured_table := r if {
	some r in input.configuration.root_module.resources
	r.address == "aws_dynamodb_table.intake"
}

planned_table := r if {
	some r in input.planned_values.root_module.resources
	r.address == "aws_dynamodb_table.intake"
}

is_customer_managed_key_ref(ref) if contains(ref, "aws_kms_key.")
is_customer_managed_key_ref(ref) if contains(ref, "phi_kms_key_arn")
