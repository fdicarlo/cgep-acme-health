package compliance.hipaa.dynamodb_kms_test

import rego.v1
import data.compliance.hipaa.dynamodb_kms

compliant := {"configuration":{"root_module":{"resources":[{
  "address":"aws_dynamodb_table.intake",
  "type":"aws_dynamodb_table",
  "expressions":{"server_side_encryption":[{}]}
}]}}}

noncompliant := {"configuration":{"root_module":{"resources":[{
  "address":"aws_dynamodb_table.intake",
  "type":"aws_dynamodb_table",
  "expressions":{}
}]}}}

test_compliant_passes if { count(dynamodb_kms.deny) == 0 with input as compliant }
test_noncompliant_fails if { some msg in dynamodb_kms.deny with input as noncompliant; contains(msg, "164.312(a)(2)(iv)") }