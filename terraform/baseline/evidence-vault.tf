######################################################################
# Evidence vault — immutable storage for CI/CD audit artifacts.
#
# Object Lock must be enabled when the bucket is created. Versioning,
# retention, encryption, public access blocking, TLS enforcement, and a
# deletion guard make the vault suitable for signed deployment evidence.
######################################################################

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "evidence_vault" {
  bucket              = "${var.name_prefix}-evidence-vault-${var.suffix}"
  object_lock_enabled = true

  tags = {
    Name = "${var.name_prefix}-evidence-vault"
  }
}

resource "aws_s3_bucket_versioning" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    default_retention {
      mode = var.evidence_vault_lock_mode
      days = var.evidence_vault_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence_vault]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.phi.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence_vault" {
  bucket                  = aws_s3_bucket.evidence_vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "evidence_vault" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.evidence_vault.arn,
      "${aws_s3_bucket.evidence_vault.arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "DenyBucketDeletionExceptRoot"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:DeleteBucket"]
    resources = [aws_s3_bucket.evidence_vault.arn]

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_s3_bucket_policy" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id
  policy = data.aws_iam_policy_document.evidence_vault.json
}
