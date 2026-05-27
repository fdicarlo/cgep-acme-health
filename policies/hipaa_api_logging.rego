# METADATA
# title: HIPAA 164.312(b) - API Gateway access logging required
# custom:
#   framework: hipaa-security-rule
#   controls: ["164.312(b)"]
#   severity: medium
#   remediation: "Configure aws_apigatewayv2_stage.default access_log_settings with a CloudWatch Logs destination and structured access log format."
package compliance.hipaa.api_logging

import rego.v1

deny contains msg if {
	not has_access_logging
	msg := "[HIPAA 164.312(b)] aws_apigatewayv2_stage.default: API Gateway access logging must be configured."
}

has_access_logging if {
	some r in input.planned_values.root_module.resources
	r.address == "aws_apigatewayv2_stage.default"
	stage_has_planned_logging(r)
}

has_access_logging if {
	some r in input.planned_values.root_module.resources
	r.address == "aws_apigatewayv2_stage.default"
	stage_has_configured_logging
}

stage_has_planned_logging(r) if {
	settings := r.values.access_log_settings[0]
	settings.destination_arn
	settings.format
	settings.destination_arn != ""
	settings.format != ""
}

stage_has_configured_logging if {
	some r in input.configuration.root_module.resources
	r.address == "aws_apigatewayv2_stage.default"
	settings := r.expressions.access_log_settings[0]
	settings.destination_arn.references
	settings.format
}
