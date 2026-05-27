######################################################################
# KMS — customer-managed key for PHI-bearing workload data stores.
#
# The workload consumes this baseline output for S3 uploads and DynamoDB
# encryption so cryptographic custody is centralized in the GRC layer.
######################################################################

resource "aws_kms_key" "phi" {
  description             = "CMK for Acme Health PHI workload"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name = "${var.name_prefix}-phi-key"
  }
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${var.name_prefix}-phi-${var.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}
