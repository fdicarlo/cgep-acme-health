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
	cfg := uploads_versioning_config
	planned := planned_versioning(cfg.address)
	planned.values.versioning_configuration[0].status == "Enabled"
}

uploads_versioning_config := r if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	references_uploads_bucket(ref)
}

planned_versioning(addr) := r if {
	some r in input.planned_values.root_module.resources
	r.address == addr
}

references_uploads_bucket(ref) if ref == "aws_s3_bucket.uploads"
references_uploads_bucket(ref) if ref == "aws_s3_bucket.uploads.id"
references_uploads_bucket(ref) if ref == "aws_s3_bucket.uploads.bucket"
