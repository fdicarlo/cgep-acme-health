package compliance.hipaa.iam_least_privilege_test

import rego.v1
import data.compliance.hipaa.iam_least_privilege

compliant := {"planned_values":{"root_module":{"resources":[{
  "address":"aws_iam_role_policy.lambda_inline",
  "values":{"policy":"{\"Statement\":[{\"Action\":[\"dynamodb:PutItem\",\"s3:PutObject\"]}]}"}
}]}}}

noncompliant := {"planned_values":{"root_module":{"resources":[{
  "address":"aws_iam_role_policy.lambda_inline",
  "values":{"policy":"{\"Statement\":[{\"Action\":[\"dynamodb:*\"]}]}"}
}]}}}

test_compliant_passes if { count(iam_least_privilege.deny) == 0 with input as compliant }
test_noncompliant_fails if { some msg in iam_least_privilege.deny with input as noncompliant; contains(msg, "wildcard action") }