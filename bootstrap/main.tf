######################################################################
# Bootstrap (applied once, by a human, with local state).
# Creates what the pipeline itself depends on and must not manage:
#   - S3 remote state bucket
#   - GitHub OIDC trust + two roles (plan on PRs, apply on main)
# OIDC pattern adapted from cgep Lab 4.3.
######################################################################

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "github_org" {
  type    = string
  default = "jonathansteward"
}

variable "github_repo" {
  type    = string
  default = "cgep-capstone"
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project   = "acme-health-intake"
      ManagedBy = "terraform-bootstrap"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  repo       = "${var.github_org}/${var.github_repo}"
}

# ---------------- remote state ----------------
resource "aws_s3_bucket" "state" {
  bucket = "acme-health-intake-tfstate-${local.account_id}"
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "state_tls" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
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

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state_tls.json
}

# ---------------- GitHub OIDC ----------------
# The account already has the GitHub provider (one per URL per account).
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "trust_pr" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${local.repo}:pull_request"]
    }
  }
}

data "aws_iam_policy_document" "trust_main" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${local.repo}:ref:refs/heads/main"]
    }
  }
}

# ---- plan role: metadata-only read + write evidence/ in the vault ----
resource "aws_iam_role" "plan" {
  name               = "cgep-capstone-gh-plan"
  assume_role_policy = data.aws_iam_policy_document.trust_pr.json
}

# SecurityAudit is metadata-only (no dynamodb:GetItem / s3:GetObject on PHI).
resource "aws_iam_role_policy_attachment" "plan_audit" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

data "aws_iam_policy_document" "plan_extra" {
  statement {
    sid       = "ReadState"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
  }
  statement {
    sid       = "ReadWorkloadConfigMetadata"
    actions   = ["lambda:GetFunction*", "lambda:ListVersionsByFunction", "apigateway:GET", "sqs:GetQueueAttributes", "sqs:ListQueueTags", "dynamodb:DescribeContinuousBackups", "dynamodb:DescribeTimeToLive", "dynamodb:ListTagsOfResource", "kms:GetKeyRotationStatus", "kms:ListResourceTags", "logs:ListTagsForResource", "s3:GetBucket*", "s3:GetEncryptionConfiguration", "s3:GetLifecycleConfiguration", "s3:GetReplicationConfiguration", "s3:GetAccelerateConfiguration", "s3:GetObjectLockConfiguration"]
    resources = ["*"]
  }
  statement {
    sid       = "WriteEvidence"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["arn:aws:s3:::acme-health-intake-evidence-vault-*/evidence/*"]
  }
  statement {
    sid       = "EvidenceKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["arn:aws:kms:${var.aws_region}:${local.account_id}:key/*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "plan_extra" {
  name   = "plan-extra"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.plan_extra.json
}

# ---- apply role: manage the workload; cannot read PHI or weaken the vault ----
resource "aws_iam_role" "apply" {
  name               = "cgep-capstone-gh-apply"
  assume_role_policy = data.aws_iam_policy_document.trust_main.json
}

data "aws_iam_policy_document" "apply" {
  statement {
    sid = "ManageWorkloadServices"
    actions = [
      "ec2:*", "kms:*", "lambda:*", "apigateway:*", "logs:*", "sqs:*",
      "cloudtrail:*", "dynamodb:*", "s3:*", "xray:*",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "IamReadAll"
    actions   = ["iam:Get*", "iam:List*"]
    resources = ["*"]
  }
  statement {
    sid       = "IamManageWorkloadRoles"
    actions   = ["iam:*"]
    resources = ["arn:aws:iam::${local.account_id}:role/acme-health-intake-*", "arn:aws:iam::${local.account_id}:policy/acme-health-intake-*"]
  }
  statement {
    sid       = "ServiceLinkedRoles"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]
  }
  statement {
    sid    = "DenyPhiDataPlane"
    effect = "Deny"
    actions = [
      "dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan",
      "dynamodb:PartiQLSelect", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "DenyReadUploads"
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["arn:aws:s3:::acme-health-intake-uploads-*/*"]
  }
  statement {
    sid       = "DenyVaultTamper"
    effect    = "Deny"
    actions   = ["s3:BypassGovernanceRetention", "s3:DeleteObjectVersion", "s3:PutObjectRetention", "s3:PutObjectLegalHold"]
    resources = ["arn:aws:s3:::acme-health-intake-evidence-vault-*", "arn:aws:s3:::acme-health-intake-evidence-vault-*/*"]
  }
}

resource "aws_iam_role_policy" "apply" {
  name   = "apply"
  role   = aws_iam_role.apply.id
  policy = data.aws_iam_policy_document.apply.json
}

output "state_bucket" {
  value = aws_s3_bucket.state.id
}

output "plan_role_arn" {
  value = aws_iam_role.plan.arn
}

output "apply_role_arn" {
  value = aws_iam_role.apply.arn
}
