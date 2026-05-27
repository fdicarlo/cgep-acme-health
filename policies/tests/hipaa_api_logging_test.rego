package compliance.hipaa.api_logging_test

import rego.v1
import data.compliance.hipaa.api_logging

compliant := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_apigatewayv2_stage.default",
	"values": {"access_log_settings": [{"destination_arn": "arn:aws:logs:x", "format": "json"}]},
}]}}}

missing_logging := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_apigatewayv2_stage.default",
	"values": {},
}]}}}

missing_stage := {"planned_values": {"root_module": {"resources": []}}}

empty_logging := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_apigatewayv2_stage.default",
	"values": {"access_log_settings": [{"destination_arn": "", "format": ""}]},
}]}}}

configured_logging_with_unknown_destination := {
	"configuration": {"root_module": {"resources": [{
		"address": "aws_apigatewayv2_stage.default",
		"expressions": {"access_log_settings": [{
			"destination_arn": {"references": ["aws_cloudwatch_log_group.api_access.arn"]},
			"format": {},
		}]},
	}]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_apigatewayv2_stage.default",
		"values": {"access_log_settings": [{"format": "json"}]},
	}]}},
}

test_compliant_passes if { count(api_logging.deny) == 0 with input as compliant }
test_missing_logging_fails if { some msg in api_logging.deny with input as missing_logging; contains(msg, "164.312(b)") }
test_missing_stage_fails if { some msg in api_logging.deny with input as missing_stage; contains(msg, "164.312(b)") }
test_empty_logging_fails if { some msg in api_logging.deny with input as empty_logging; contains(msg, "164.312(b)") }
test_configured_logging_with_unknown_destination_passes if { count(api_logging.deny) == 0 with input as configured_logging_with_unknown_destination }
