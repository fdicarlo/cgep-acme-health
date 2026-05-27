package compliance.hipaa.dynamodb_pitr_test

import data.compliance.hipaa.dynamodb_pitr
import rego.v1

compliant := {
	"configuration": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"expressions": {"point_in_time_recovery": [{"enabled": {"constant_value": true}}]},
	}]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"values": {"point_in_time_recovery": [{"enabled": true}]},
	}]}},
}

disabled := {
	"configuration": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"expressions": {"point_in_time_recovery": [{"enabled": {"constant_value": false}}]},
	}]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"values": {"point_in_time_recovery": [{"enabled": false}]},
	}]}},
}

missing := {
	"configuration": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"expressions": {},
	}]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"values": {},
	}]}},
}

test_compliant_passes if count(dynamodb_pitr.deny) == 0 with input as compliant

test_disabled_fails if {
	some msg in dynamodb_pitr.deny with input as disabled
	contains(msg, "164.308(a)(7)")
}

test_missing_fails if {
	some msg in dynamodb_pitr.deny with input as missing
	contains(msg, "164.308(a)(7)")
}
