package compliance.hipaa.s3_tls_test

import data.compliance.hipaa.s3_tls
import rego.v1

tls_policy := `{"Statement":[{"Sid":"DenyInsecureTransport","Effect":"Deny","Action":"s3:*","Resource":["arn:aws:s3:::acme-health-intake-uploads-abc","arn:aws:s3:::acme-health-intake-uploads-abc/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`

allow_only_policy := `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::acme-health-intake-uploads-abc/*"}]}`

compliant := {
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.uploads_tls",
		"type": "aws_s3_bucket_policy",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
	}]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.uploads_tls",
		"type": "aws_s3_bucket_policy",
		"values": {"policy": tls_policy},
	}]}},
}

wrong_policy_body := {
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.uploads_tls",
		"type": "aws_s3_bucket_policy",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
	}]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.uploads_tls",
		"type": "aws_s3_bucket_policy",
		"values": {"policy": allow_only_policy},
	}]}},
}

decoy_bucket_policy := {
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.other",
		"type": "aws_s3_bucket_policy",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.other.id"]}},
	}]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.other",
		"type": "aws_s3_bucket_policy",
		"values": {"policy": tls_policy},
	}]}},
}

configured_doc_statement := {
	"actions": {"constant_value": ["s3:*"]},
	"condition": [{
		"test": {"constant_value": "Bool"},
		"values": {"constant_value": ["false"]},
		"variable": {"constant_value": "aws:SecureTransport"},
	}],
	"effect": {"constant_value": "Deny"},
	"principals": [{
		"identifiers": {"constant_value": ["*"]},
		"type": {"constant_value": "*"},
	}],
	"resources": {"references": ["aws_s3_bucket.uploads.arn", "aws_s3_bucket.uploads"]},
}

unknown_policy_with_configured_doc := {
	"configuration": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket_policy.uploads_tls",
			"type": "aws_s3_bucket_policy",
			"expressions": {
				"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
				"policy": {"references": ["data.aws_iam_policy_document.uploads_tls.json", "data.aws_iam_policy_document.uploads_tls"]},
			},
		},
		{
			"address": "data.aws_iam_policy_document.uploads_tls",
			"type": "aws_iam_policy_document",
			"expressions": {"statement": [configured_doc_statement]},
		},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.uploads_tls",
		"type": "aws_s3_bucket_policy",
		"values": {},
	}]}},
}

unknown_policy_with_wrong_configured_doc := {
	"configuration": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket_policy.uploads_tls",
			"type": "aws_s3_bucket_policy",
			"expressions": {
				"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
				"policy": {"references": ["data.aws_iam_policy_document.uploads_tls.json", "data.aws_iam_policy_document.uploads_tls"]},
			},
		},
		{
			"address": "data.aws_iam_policy_document.uploads_tls",
			"type": "aws_iam_policy_document",
			"expressions": {"statement": [object.union(configured_doc_statement, {"condition": [{
				"test": {"constant_value": "Bool"},
				"values": {"constant_value": ["true"]},
				"variable": {"constant_value": "aws:SecureTransport"},
			}]})]},
		},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.uploads_tls",
		"type": "aws_s3_bucket_policy",
		"values": {},
	}]}},
}

test_compliant_passes if count(s3_tls.deny) == 0 with input as compliant
test_unknown_policy_with_configured_doc_passes if count(s3_tls.deny) == 0 with input as unknown_policy_with_configured_doc

test_wrong_policy_body_fails if {
	some msg in s3_tls.deny with input as wrong_policy_body
	contains(msg, "164.312(e)(1)")
}

test_unknown_policy_with_wrong_configured_doc_fails if {
	some msg in s3_tls.deny with input as unknown_policy_with_wrong_configured_doc
	contains(msg, "164.312(e)(1)")
}

test_decoy_bucket_policy_fails if {
	some msg in s3_tls.deny with input as decoy_bucket_policy
	contains(msg, "164.312(e)(1)")
}
