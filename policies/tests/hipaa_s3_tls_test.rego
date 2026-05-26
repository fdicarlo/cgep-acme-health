package compliance.hipaa.s3_tls_test

import rego.v1
import data.compliance.hipaa.s3_tls

compliant := {"configuration":{"root_module":{"resources":[{
  "type":"aws_s3_bucket_policy",
  "expressions":{"bucket":{"references":["aws_s3_bucket.uploads.id"]}}
}]}}}

noncompliant := {"configuration":{"root_module":{"resources":[]}}}

test_compliant_passes if { count(s3_tls.deny) == 0 with input as compliant }
test_noncompliant_fails if { some msg in s3_tls.deny with input as noncompliant; contains(msg, "164.312(e)(1)") }