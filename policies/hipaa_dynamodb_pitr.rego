# METADATA
# title: HIPAA 164.308(a)(7) - DynamoDB must enable point-in-time recovery
# custom:
#   framework: hipaa-security-rule
#   controls: ["164.308(a)(7)"]
#   severity: medium
#   remediation: "Enable point_in_time_recovery on aws_dynamodb_table.intake so PHI records can be restored after accidental deletion or overwrite."
package compliance.hipaa.dynamodb_pitr

import rego.v1

deny contains msg if {
	not has_pitr
	msg := "[HIPAA 164.308(a)(7)] aws_dynamodb_table.intake: DynamoDB point-in-time recovery must be enabled for PHI record recoverability."
}

has_pitr if {
	cfg := configured_table
	cfg.expressions.point_in_time_recovery[0].enabled.constant_value == true

	planned := planned_table
	planned.values.point_in_time_recovery[0].enabled == true
}

configured_table := r if {
	some r in input.configuration.root_module.resources
	r.address == "aws_dynamodb_table.intake"
}

planned_table := r if {
	some r in input.planned_values.root_module.resources
	r.address == "aws_dynamodb_table.intake"
}
