# METADATA
# title: HIPAA 164.312(a)(1) - Lambda IAM policy must not use wildcard data actions
# custom:
#   framework: hipaa-security-rule
#   controls: ["164.312(a)(1)"]
#   severity: critical
package compliance.hipaa.iam_least_privilege

import rego.v1

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.address == "aws_iam_role_policy.lambda_inline"
	policy := json.unmarshal(r.values.policy)
	some stmt in policy.Statement
	some action in object.get(stmt, "Action", [])
	endswith(action, ":*")
	msg := sprintf("[HIPAA 164.312(a)(1)] %s: wildcard action %s is not allowed for PHI workload access.", [r.address, action])
}