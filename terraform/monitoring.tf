######################################################################
# Continuous monitoring & detection (SOC 2 CC7.2).
#
# The policy gate (Layer 2) only catches misconfiguration at plan time,
# in CI. It says nothing about a change made outside Terraform (console,
# CLI, another pipeline) after deploy. These AWS Config rules close that
# gap: each one re-evaluates continuously and maps 1:1 to a starter gap
# and its Rego policy, so an auditor can trace the same control through
# code (policies/soc2/*.rego), signed evidence (the vault) and runtime
# (these rules) at once.
#
# Uses the account's existing Config recorder/delivery channel (only one
# recorder is allowed per region; this account already has one — see
# `aws configservice describe-configuration-recorders`). Config rules
# attach to that recorder without owning it.
######################################################################

# ---- alert routing ----
resource "aws_sns_topic" "compliance_alerts" {
  name              = "${local.name_prefix}-compliance-alerts-${local.suffix}"
  kms_master_key_id = aws_kms_key.evidence_key.id
}

# A single topic can only have one resource policy. Every principal that
# needs to publish (EventBridge, CloudTrail, S3 — see the S3 event
# notification statement further down) is a statement in this one
# document, applied by the one aws_sns_topic_policy resource below. Two
# separate aws_sns_topic_policy resources on the same topic ARN would
# silently overwrite each other on alternating applies instead of merging
# — caught via `terraform plan` showing perpetual drift during review.
data "aws_iam_policy_document" "compliance_alerts_topic" {
  statement {
    sid       = "AllowEventBridgePublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.compliance_alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowCloudTrailPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.compliance_alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowS3Publish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.compliance_alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
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
  }
}

resource "aws_sns_topic_policy" "compliance_alerts" {
  arn    = aws_sns_topic.compliance_alerts.arn
  policy = data.aws_iam_policy_document.compliance_alerts_topic.json
}

# EventBridge rule: any AWS Config rule going NON_COMPLIANT fires an alert.
# This is the "detects drift or misconfiguration in real time" mechanism —
# distinct from and complementary to the CI-time Conftest gate.
resource "aws_cloudwatch_event_rule" "config_noncompliant" {
  name        = "${local.name_prefix}-config-noncompliant-${local.suffix}"
  description = "Fires when any targeted compliance Config rule goes NON_COMPLIANT."
  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      messageType         = ["ComplianceChangeNotification"]
      newEvaluationResult = { complianceType = ["NON_COMPLIANT"] }
    }
  })
}

resource "aws_cloudwatch_event_target" "config_noncompliant_sns" {
  rule      = aws_cloudwatch_event_rule.config_noncompliant.name
  target_id = "compliance-alerts"
  arn       = aws_sns_topic.compliance_alerts.arn
}

# ---- targeted Config rules: one per gap-closing control ----
# Each source_identifier is an AWS managed rule; each maps to the same
# gap ID and SOC 2 criterion as a Rego policy in policies/soc2/.

resource "aws_config_config_rule" "s3_sse" {
  name = "${local.name_prefix}-s3-sse-${local.suffix}"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
  tags = { Gap = "GAP-01", Control = "CC6.1" }
}

resource "aws_config_config_rule" "s3_tls_only" {
  name = "${local.name_prefix}-s3-tls-only-${local.suffix}"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
  tags = { Gap = "GAP-03", Control = "CC6.7" }
}

resource "aws_config_config_rule" "s3_versioning" {
  name = "${local.name_prefix}-s3-versioning-${local.suffix}"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
  tags = { Gap = "GAP-04", Control = "A1.2" }
}

resource "aws_config_config_rule" "dynamodb_cmk" {
  name = "${local.name_prefix}-dynamodb-cmk-${local.suffix}"
  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_TABLE_ENCRYPTED_KMS"
  }
  tags = { Gap = "GAP-02", Control = "CC6.1" }
}

resource "aws_config_config_rule" "lambda_in_vpc" {
  name = "${local.name_prefix}-lambda-in-vpc-${local.suffix}"
  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_INSIDE_VPC"
  }
  tags = { Gap = "GAP-05", Control = "CC6.6" }
}

resource "aws_config_config_rule" "iam_no_admin" {
  name = "${local.name_prefix}-iam-no-admin-${local.suffix}"
  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }
  tags = { Gap = "GAP-07", Control = "CC6.3" }
}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  name = "${local.name_prefix}-cloudtrail-enabled-${local.suffix}"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }
  tags = { Control = "CC7.2" }
}

resource "aws_config_config_rule" "api_gw_logging" {
  name = "${local.name_prefix}-api-gw-logging-${local.suffix}"
  source {
    owner             = "AWS"
    source_identifier = "API_GW_EXECUTION_LOGGING_ENABLED"
  }
  tags = { Gap = "GAP-08", Control = "CC7.2" }
}

######################################################################
# VPC flow logs (CC7.2 / checkov CKV2_AWS_11) and a locked-down default
# security group (checkov CKV2_AWS_12).
######################################################################

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc-flow-logs/${local.name_prefix}-${local.suffix}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.evidence_key.arn
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${local.name_prefix}-flow-logs-${local.suffix}"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

data "aws_iam_policy_document" "flow_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "flow-logs-write"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs.json
}

resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.vpc_flow_logs.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn
}

# Every VPC gets a default security group whether we reference it or not;
# lock it down explicitly rather than leave the AWS default (which allows
# all traffic between anything attached to it).
resource "aws_default_security_group" "main" {
  vpc_id = aws_vpc.main.id
  # No ingress/egress blocks: deny-by-default.
}

######################################################################
# CloudTrail -> CloudWatch Logs (checkov CKV2_AWS_10): real-time log
# delivery in addition to the S3 archive, so CloudWatch-based alarms and
# Log Insights queries can run against trail events without an S3 read.
######################################################################

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${local.name_prefix}-${local.suffix}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.evidence_key.arn
}

data "aws_iam_policy_document" "cloudtrail_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_logs" {
  name               = "${local.name_prefix}-cloudtrail-logs-${local.suffix}"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_logs_assume.json
}

data "aws_iam_policy_document" "cloudtrail_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  name   = "cloudtrail-logs-write"
  role   = aws_iam_role.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_logs.json
}

######################################################################
# S3 event notifications (checkov CKV2_AWS_62) on the three
# compliance-relevant buckets, published to the same alerting topic used
# for Config drift. A new object landing in the PHI uploads bucket, the
# evidence vault or the CloudTrail bucket is itself a security-relevant
# event worth surfacing, distinct from Config's control-state checks.
######################################################################

# The AllowS3Publish statement lives in data.aws_iam_policy_document.compliance_alerts_topic
# above, alongside EventBridge and CloudTrail — one topic, one policy resource.
resource "aws_s3_bucket_notification" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  topic {
    topic_arn = aws_sns_topic.compliance_alerts.arn
    events    = ["s3:ObjectCreated:*"]
  }
  depends_on = [aws_sns_topic_policy.compliance_alerts]
}

resource "aws_s3_bucket_notification" "vault" {
  bucket = aws_s3_bucket.vault.id
  topic {
    topic_arn = aws_sns_topic.compliance_alerts.arn
    events    = ["s3:ObjectCreated:*"]
  }
  depends_on = [aws_sns_topic_policy.compliance_alerts]
}

resource "aws_s3_bucket_notification" "trail" {
  bucket = aws_s3_bucket.trail.id
  topic {
    topic_arn = aws_sns_topic.compliance_alerts.arn
    events    = ["s3:ObjectCreated:*"]
  }
  depends_on = [aws_sns_topic_policy.compliance_alerts]
}
