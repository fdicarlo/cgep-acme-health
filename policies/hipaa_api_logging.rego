# METADATA
# title: HIPAA 164.312(b) - API Gateway access logging required
# custom:
#   framework: hipaa-security-rule
#   controls: ["164.312(b)"]
#   severity: medium
package compliance.hipaa.api_logging

import rego.v1

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.address == "aws_apigatewayv2_stage.default"
	not r.values.access_log_settings
	msg := "[HIPAA 164.312(b)] aws_apigatewayv2_stage.default: API Gateway access logging must be configured."
}