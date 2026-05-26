# METADATA
# title: HIPAA 164.308(a)(7) - PHI bucket versioning required
# custom:
#   framework: hipaa-security-rule
#   controls: ["164.308(a)(7)"]
#   severity: medium
package compliance.hipaa.s3_versioning

import rego.v1

deny contains msg if {
	not has_versioning
	msg := "[HIPAA 164.308(a)(7)] aws_s3_bucket.uploads: PHI uploads bucket must have versioning enabled."
}

has_versioning if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	r.values.versioning_configuration[0].status == "Enabled"
}