# Unit tests for the SOC 2 suite: one passing and one failing fixture per policy.
# Run: opa test ./policies
package soc2.tests

import data.compliance.soc2.a1_2_s3_versioning
import data.compliance.soc2.cc6_1_dynamodb_cmk
import data.compliance.soc2.cc6_1_s3_cmk
import data.compliance.soc2.cc6_3_iam_least_privilege
import data.compliance.soc2.cc6_6_lambda_vpc
import data.compliance.soc2.cc6_7_s3_tls
import data.compliance.soc2.cc7_2_api_logging
import data.compliance.soc2.cc7_2_cloudtrail
import data.compliance.soc2.cc7_2_lambda_observability
import rego.v1

res(type, name, expr) := {"mode": "managed", "type": type, "name": name, "expressions": expr}

doc(name, expr) := {"mode": "data", "type": "aws_iam_policy_document", "name": name, "expressions": expr}

cfg(rs) := {"configuration": {"root_module": {"resources": rs}}}

bucket_ref := {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}

bucket := res("aws_s3_bucket", "b", {})

# ---- CC6.1 S3 CMK (GAP-01) ----
sse(algo) := res("aws_s3_bucket_server_side_encryption_configuration", "b", {
	"bucket": bucket_ref,
	"rule": [{"apply_server_side_encryption_by_default": [{
		"sse_algorithm": {"constant_value": algo},
		"kms_master_key_id": {"references": ["aws_kms_key.k.arn", "aws_kms_key.k"]},
	}]}],
})

test_s3_cmk_pass if count(cc6_1_s3_cmk.deny) == 0 with input as cfg([bucket, sse("aws:kms")])

test_s3_cmk_fail_no_sse if count(cc6_1_s3_cmk.deny) == 1 with input as cfg([bucket])

test_s3_cmk_fail_sse_s3 if count(cc6_1_s3_cmk.deny) == 1 with input as cfg([bucket, sse("AES256")])

# ---- CC6.1 DynamoDB CMK (GAP-02) ----
test_ddb_cmk_pass if {
	t := res("aws_dynamodb_table", "t", {"server_side_encryption": [{
		"enabled": {"constant_value": true},
		"kms_key_arn": {"references": ["aws_kms_key.k.arn"]},
	}]})
	count(cc6_1_dynamodb_cmk.deny) == 0 with input as cfg([t])
}

test_ddb_cmk_fail if {
	t := res("aws_dynamodb_table", "t", {})
	count(cc6_1_dynamodb_cmk.deny) == 1 with input as cfg([t])
}

# ---- CC6.7 TLS (GAP-03) ----
tls_doc := doc("tls", {"statement": [{
	"effect": {"constant_value": "Deny"},
	"condition": [{
		"variable": {"constant_value": "aws:SecureTransport"},
		"values": {"constant_value": ["false"]},
	}],
}]})

tls_policy := res("aws_s3_bucket_policy", "b", {
	"bucket": bucket_ref,
	"policy": {"references": ["data.aws_iam_policy_document.tls.json", "data.aws_iam_policy_document.tls"]},
})

test_tls_pass if count(cc6_7_s3_tls.deny) == 0 with input as cfg([bucket, tls_doc, tls_policy])

test_tls_fail_no_policy if count(cc6_7_s3_tls.deny) == 1 with input as cfg([bucket])

test_tls_fail_allow_statement if {
	allow_doc := doc("tls", {"statement": [{"effect": {"constant_value": "Allow"}, "condition": []}]})
	count(cc6_7_s3_tls.deny) == 1 with input as cfg([bucket, allow_doc, tls_policy])
}

# ---- A1.2 versioning (GAP-04) ----
test_versioning_pass if {
	v := res("aws_s3_bucket_versioning", "b", {
		"bucket": bucket_ref,
		"versioning_configuration": [{"status": {"constant_value": "Enabled"}}],
	})
	count(a1_2_s3_versioning.deny) == 0 with input as cfg([bucket, v])
}

test_versioning_fail_missing if count(a1_2_s3_versioning.deny) == 1 with input as cfg([bucket])

test_versioning_fail_suspended if {
	v := res("aws_s3_bucket_versioning", "b", {
		"bucket": bucket_ref,
		"versioning_configuration": [{"status": {"constant_value": "Suspended"}}],
	})
	count(a1_2_s3_versioning.deny) == 1 with input as cfg([bucket, v])
}

# ---- CC6.6 Lambda VPC (GAP-05) ----
test_vpc_pass if {
	f := res("aws_lambda_function", "f", {"vpc_config": [{
		"subnet_ids": {"references": ["aws_subnet.private"]},
		"security_group_ids": {"references": ["aws_security_group.s.id"]},
	}]})
	count(cc6_6_lambda_vpc.deny) == 0 with input as cfg([f])
}

test_vpc_fail if {
	f := res("aws_lambda_function", "f", {})
	count(cc6_6_lambda_vpc.deny) == 1 with input as cfg([f])
}

# ---- CC7.2 Lambda observability (GAP-06) ----
test_observability_pass if {
	f := res("aws_lambda_function", "f", {
		"tracing_config": [{"mode": {"constant_value": "Active"}}],
		"dead_letter_config": [{"target_arn": {"references": ["aws_sqs_queue.d.arn"]}}],
	})
	count(cc7_2_lambda_observability.deny) == 0 with input as cfg([f])
}

test_observability_fail_both if {
	f := res("aws_lambda_function", "f", {"tracing_config": [{"mode": {"constant_value": "PassThrough"}}]})
	count(cc7_2_lambda_observability.deny) == 2 with input as cfg([f])
}

# ---- CC6.3 least privilege (GAP-07) ----
role_policy := res("aws_iam_role_policy", "p", {"policy": {"references": ["data.aws_iam_policy_document.d.json", "data.aws_iam_policy_document.d"]}})

allow_doc(actions) := doc("d", {"statement": [{"effect": {"constant_value": "Allow"}, "actions": {"constant_value": actions}}]})

test_iam_pass if count(cc6_3_iam_least_privilege.deny) == 0 with input as cfg([role_policy, allow_doc(["dynamodb:PutItem"])])

test_iam_fail_service_wildcard if count(cc6_3_iam_least_privilege.deny) == 1 with input as cfg([role_policy, allow_doc(["s3:*"])])

test_iam_fail_star if count(cc6_3_iam_least_privilege.deny) == 1 with input as cfg([role_policy, allow_doc(["*"])])

test_iam_fail_admin_attachment if {
	a := res("aws_iam_role_policy_attachment", "a", {"policy_arn": {"constant_value": "arn:aws:iam::aws:policy/AdministratorAccess"}})
	count(cc6_3_iam_least_privilege.deny) == 1 with input as cfg([a])
}

# ---- CC7.2 API logging (GAP-08) ----
test_api_pass if {
	s := res("aws_apigatewayv2_stage", "s", {
		"access_log_settings": [{"destination_arn": {"references": ["aws_cloudwatch_log_group.l.arn"]}}],
		"default_route_settings": [{"throttling_rate_limit": {"constant_value": 10}}],
	})
	count(cc7_2_api_logging.deny) == 0 with input as cfg([s])
}

test_api_fail_both if {
	s := res("aws_apigatewayv2_stage", "s", {})
	count(cc7_2_api_logging.deny) == 2 with input as cfg([s])
}

# ---- CC7.2 CloudTrail ----
test_trail_pass if {
	t := res("aws_cloudtrail", "t", {
		"is_multi_region_trail": {"constant_value": true},
		"enable_log_file_validation": {"constant_value": true},
	})
	count(cc7_2_cloudtrail.deny) == 0 with input as cfg([t])
}

test_trail_fail_absent if count(cc7_2_cloudtrail.deny) == 1 with input as cfg([])

test_trail_fail_single_region if {
	t := res("aws_cloudtrail", "t", {
		"is_multi_region_trail": {"constant_value": false},
		"enable_log_file_validation": {"constant_value": true},
	})
	count(cc7_2_cloudtrail.deny) == 1 with input as cfg([t])
}
