# METADATA
# title: CC6.1 - S3 buckets encrypted with a customer-managed KMS key
# description: Every aws_s3_bucket needs an SSE configuration using aws:kms with a customer key, not the AWS-managed SSE-S3 default.
# custom:
#   framework: soc2
#   controls:
#     - "CC6.1"
#   gaps:
#     - "GAP-01"
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = aws:kms and kms_master_key_id = aws_kms_key.<key>.arn."
package compliance.soc2.cc6_1_s3_cmk

import data.soc2.lib
import rego.v1

deny contains msg if {
	some b in lib.resources("aws_s3_bucket")
	not encrypted_with_cmk(b)
	not is_log_delivery_destination(b)
	msg := sprintf("[SOC2 CC6.1] %s: bucket is not encrypted with a customer-managed KMS key (GAP-01). Add an aws:kms SSE configuration.", [lib.addr(b)])
}

# S3 server access log delivery only supports SSE-S3 on the destination
# bucket, not a customer CMK (an AWS platform constraint). A bucket tagged
# as such is exempt from this control; see terraform/logging.tf.
is_log_delivery_destination(b) if {
	b.expressions.tags.constant_value.Purpose == "s3-access-log-destination"
}

encrypted_with_cmk(b) if {
	some c in lib.resources("aws_s3_bucket_server_side_encryption_configuration")
	lib.refers_to(c.expressions.bucket, lib.addr(b))
	some rule in c.expressions.rule
	some d in rule.apply_server_side_encryption_by_default
	d.sse_algorithm.constant_value == "aws:kms"
	lib.has_cmk(d.kms_master_key_id)
}
