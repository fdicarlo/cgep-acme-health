package compliance.hipaa.s3_versioning_test

import rego.v1
import data.compliance.hipaa.s3_versioning

compliant := {"planned_values":{"root_module":{"resources":[{
  "type":"aws_s3_bucket_versioning",
  "values":{"versioning_configuration":[{"status":"Enabled"}]}
}]}}}

noncompliant := {"planned_values":{"root_module":{"resources":[]}}}

test_compliant_passes if { count(s3_versioning.deny) == 0 with input as compliant }
test_noncompliant_fails if { some msg in s3_versioning.deny with input as noncompliant; contains(msg, "164.308(a)(7)") }