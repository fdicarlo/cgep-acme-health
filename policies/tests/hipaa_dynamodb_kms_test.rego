package compliance.hipaa.dynamodb_kms_test

import rego.v1
import data.compliance.hipaa.dynamodb_kms

compliant := {
	"configuration": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"expressions": {"server_side_encryption": [{"kms_key_arn": {"references": ["module.grc_baseline.phi_kms_key_arn"]}}]},
	}]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"values": {"server_side_encryption": [{"enabled": true}]},
	}]}},
}

aws_managed_key := {
	"configuration": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"expressions": {"server_side_encryption": [{"kms_key_arn": {"constant_value": "alias/aws/dynamodb"}}]},
	}]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"values": {"server_side_encryption": [{"enabled": true}]},
	}]}},
}

missing_sse := {
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

test_compliant_passes if { count(dynamodb_kms.deny) == 0 with input as compliant }
test_aws_managed_key_fails if { some msg in dynamodb_kms.deny with input as aws_managed_key; contains(msg, "164.312(a)(2)(iv)") }
test_missing_sse_fails if { some msg in dynamodb_kms.deny with input as missing_sse; contains(msg, "164.312(a)(2)(iv)") }
