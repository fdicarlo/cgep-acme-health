package compliance.hipaa.s3_kms_test

import rego.v1
import data.compliance.hipaa.s3_kms

compliant := {
	"configuration": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"name": "uploads",
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"values": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]},
		},
	]}},
}

noncompliant := {
	"configuration": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"name": "uploads",
		},
	]}},
	"planned_values": {"root_module": {"resources": []}},
}

test_compliant_passes if {
	count(s3_kms.deny) == 0 with input as compliant
}

test_noncompliant_fails if {
	some msg in s3_kms.deny with input as noncompliant
	contains(msg, "HIPAA 164.312(a)(2)(iv)")
	contains(msg, "aws_s3_bucket.uploads")
}