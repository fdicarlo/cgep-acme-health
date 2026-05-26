# METADATA
# title: HIPAA 164.312(e)(1) - S3 must deny insecure transport
# custom:
#   framework: hipaa-security-rule
#   controls: ["164.312(e)(1)"]
#   severity: high
package compliance.hipaa.s3_tls

import rego.v1

deny contains msg if {
	not has_tls_deny
	msg := "[HIPAA 164.312(e)(1)] aws_s3_bucket.uploads: bucket policy must deny non-TLS requests using aws:SecureTransport=false."
}

has_tls_deny if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_policy"
	some ref in r.expressions.bucket.references
	ref == "aws_s3_bucket.uploads.id"
}