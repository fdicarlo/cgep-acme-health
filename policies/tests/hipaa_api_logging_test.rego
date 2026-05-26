package compliance.hipaa.api_logging_test

import rego.v1
import data.compliance.hipaa.api_logging

compliant := {"planned_values":{"root_module":{"resources":[{
  "address":"aws_apigatewayv2_stage.default",
  "values":{"access_log_settings":[{"destination_arn":"arn:aws:logs:x","format":"json"}]}
}]}}}

noncompliant := {"planned_values":{"root_module":{"resources":[{
  "address":"aws_apigatewayv2_stage.default",
  "values":{}
}]}}}

test_compliant_passes if { count(api_logging.deny) == 0 with input as compliant }
test_noncompliant_fails if { some msg in api_logging.deny with input as noncompliant; contains(msg, "164.312(b)") }