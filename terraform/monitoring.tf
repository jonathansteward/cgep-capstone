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
