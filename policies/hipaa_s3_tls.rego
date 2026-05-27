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
	cfg := uploads_policy_config
	planned := planned_policy(cfg.address)
	policy := json.unmarshal(planned.values.policy)
	some stmt in object.get(policy, "Statement", [])
	object.get(stmt, "Effect", "") == "Deny"
	action_matches(object.get(stmt, "Action", []))
	resource_matches(object.get(stmt, "Resource", []))
	condition := object.get(stmt, "Condition", {})
	bool_condition := object.get(condition, "Bool", {})
	object.get(bool_condition, "aws:SecureTransport", "") == "false"
}

has_tls_deny if {
	uploads_policy_config
	configured_tls_deny_document
}

uploads_policy_config := r if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_policy"
	some ref in r.expressions.bucket.references
	references_uploads_bucket(ref)
}

configured_tls_deny_document if {
	some r in input.configuration.root_module.resources
	r.address == "data.aws_iam_policy_document.uploads_tls"
	some stmt in r.expressions.statement
	stmt.effect.constant_value == "Deny"
	action_matches(stmt.actions.constant_value)
	resource_references_uploads(stmt.resources.references)
	some condition in stmt.condition
	condition.test.constant_value == "Bool"
	condition.variable.constant_value == "aws:SecureTransport"
	some value in condition.values.constant_value
	value == "false"
}

planned_policy(addr) := r if {
	some r in input.planned_values.root_module.resources
	r.address == addr
}

references_uploads_bucket(ref) if ref == "aws_s3_bucket.uploads"
references_uploads_bucket(ref) if ref == "aws_s3_bucket.uploads.arn"
references_uploads_bucket(ref) if ref == "aws_s3_bucket.uploads.id"
references_uploads_bucket(ref) if ref == "aws_s3_bucket.uploads.bucket"

action_matches(action) if action == "s3:*"

action_matches(actions) if {
	some action in actions
	action == "s3:*"
}

resource_matches(resource) if contains(resource, "acme-health-intake-uploads")

resource_matches(resources) if {
	some resource in resources
	contains(resource, "acme-health-intake-uploads")
}

resource_references_uploads(refs) if {
	some ref in refs
	references_uploads_bucket(ref)
}
