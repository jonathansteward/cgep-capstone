######################################################################
# Layer 1 — KMS customer-managed keys (adapted from cgep Lab 2.4).
#   data     : PHI at rest (S3 uploads, DynamoDB, DLQ)         SOC 2 CC6.1
#   evidence : evidence vault, CloudTrail, API access logs     SOC 2 CC6.1, CC7.2
# Both rotate annually.
######################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_kms_key" "data" {
  description             = "Acme Health PHI data key"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "data" {
  name          = "alias/${local.name_prefix}-data-${local.suffix}"
  target_key_id = aws_kms_key.data.key_id
}

data "aws_iam_policy_document" "evidence_key" {
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "CloudTrailEncrypt"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-trail"]
    }
  }

  statement {
    sid       = "CloudWatchLogsEncrypt"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:*"]
    }
  }
}

resource "aws_kms_key" "evidence_key" {
  description             = "Acme Health evidence vault / audit log key"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.evidence_key.json
}

resource "aws_kms_alias" "evidence_key" {
  name          = "alias/${local.name_prefix}-evidence-${local.suffix}"
  target_key_id = aws_kms_key.evidence_key.key_id
}
