package compliance.hipaa.s3_tls_test

import rego.v1
import data.compliance.hipaa.s3_tls

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

test_compliant_passes if { count(s3_tls.deny) == 0 with input as compliant }
test_wrong_policy_body_fails if { some msg in s3_tls.deny with input as wrong_policy_body; contains(msg, "164.312(e)(1)") }
test_decoy_bucket_policy_fails if { some msg in s3_tls.deny with input as decoy_bucket_policy; contains(msg, "164.312(e)(1)") }
