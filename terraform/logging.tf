######################################################################
# S3 server access logging (checkov CKV_AWS_18) + lifecycle rules
# (CKV2_AWS_61) for the three buckets that carry compliance-relevant
# data: uploads (PHI), the evidence vault and the CloudTrail bucket.
######################################################################

# CKV_AWS_145: S3 access-log delivery only supports SSE-S3 (or no default
# encryption) on the destination bucket, not SSE-KMS — see the SSE
# resource below.
#checkov:skip=CKV_AWS_145:S3 access-log destination buckets can't use SSE-KMS, AWS-documented constraint
resource "aws_s3_bucket" "access_logs" {
  bucket = "${local.name_prefix}-access-logs-${local.suffix}"

  # S3 server access log delivery only supports SSE-S3 on the destination
  # bucket (not a customer CMK) — an AWS platform constraint, not a policy
  # choice. This tag lets the CC6.1 Rego policy (policies/soc2/cc6_1_s3_cmk.rego)
  # exempt this one bucket from the KMS requirement instead of hardcoding
  # its resource address.
  tags = {
    Purpose = "s3-access-log-destination"
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 access logging only supports SSE-S3 (or no default encryption) on the
# destination bucket, not SSE-KMS — the log delivery group can't use a CMK.
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "expire-old-access-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = 365
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# This bucket is itself an aws_s3_bucket, so checkov's CKV_AWS_18 (every
# bucket needs access logging) would otherwise ask it to log to itself.
#checkov:skip=CKV_AWS_18:this IS the access-log destination bucket
# CKV_AWS_144 (cross-region replication) is skipped in .checkov.yaml —
# see the same note on aws_s3_bucket.uploads in main.tf.
resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = data.aws_iam_policy_document.access_logs.json
}

data "aws_iam_policy_document" "access_logs" {
  statement {
    sid       = "S3ServerAccessLogsPolicy"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.access_logs.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values = [
        aws_s3_bucket.uploads.arn,
        aws_s3_bucket.vault.arn,
        aws_s3_bucket.trail.arn,
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.access_logs.arn, "${aws_s3_bucket.access_logs.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_logging" "uploads" {
  bucket        = aws_s3_bucket.uploads.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "uploads/"
}

resource "aws_s3_bucket_logging" "vault" {
  bucket        = aws_s3_bucket.vault.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "vault/"
}

resource "aws_s3_bucket_logging" "trail" {
  bucket        = aws_s3_bucket.trail.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "cloudtrail-bucket/"
}

# ---- lifecycle rules (CKV2_AWS_61): abort stuck multipart uploads on the
# three source buckets; none need object expiration (evidence and PHI
# retention are governed by Object Lock / compliance need, not age). ----
resource "aws_s3_bucket_lifecycle_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
  depends_on = [aws_s3_bucket_versioning.vault] # Object Lock buckets require versioning first
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
