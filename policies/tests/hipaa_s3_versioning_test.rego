package compliance.hipaa.s3_versioning_test

import rego.v1
import data.compliance.hipaa.s3_versioning

compliant := {
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_versioning.uploads",
		"type": "aws_s3_bucket_versioning",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
	}]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_versioning.uploads",
		"type": "aws_s3_bucket_versioning",
		"values": {"versioning_configuration": [{"status": "Enabled"}]},
	}]}},
}

suspended_uploads := {
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_versioning.uploads",
		"type": "aws_s3_bucket_versioning",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
	}]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_versioning.uploads",
		"type": "aws_s3_bucket_versioning",
		"values": {"versioning_configuration": [{"status": "Suspended"}]},
	}]}},
}

decoy_versioning := {
	"configuration": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_versioning.other",
		"type": "aws_s3_bucket_versioning",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.other.id"]}},
	}]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_versioning.other",
		"type": "aws_s3_bucket_versioning",
		"values": {"versioning_configuration": [{"status": "Enabled"}]},
	}]}},
}

test_compliant_passes if { count(s3_versioning.deny) == 0 with input as compliant }
test_suspended_uploads_fails if { some msg in s3_versioning.deny with input as suspended_uploads; contains(msg, "164.308(a)(7)") }
test_decoy_versioning_fails if { some msg in s3_versioning.deny with input as decoy_versioning; contains(msg, "164.308(a)(7)") }
