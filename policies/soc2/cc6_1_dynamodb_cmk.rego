# METADATA
# title: CC6.1 - DynamoDB tables encrypted with a customer-managed KMS key
# description: Every aws_dynamodb_table needs server_side_encryption enabled with a customer key, not the AWS-owned default.
# custom:
#   framework: soc2
#   controls:
#     - "CC6.1"
#   gaps:
#     - "GAP-02"
#   severity: high
#   remediation: "Add server_side_encryption { enabled = true, kms_key_arn = aws_kms_key.<key>.arn } to the table."
package compliance.soc2.cc6_1_dynamodb_cmk

import data.soc2.lib
import rego.v1

deny contains msg if {
	some t in lib.resources("aws_dynamodb_table")
	not encrypted_with_cmk(t)
	msg := sprintf("[SOC2 CC6.1] %s: table uses the AWS-owned key, not a customer-managed KMS key (GAP-02).", [lib.addr(t)])
}

encrypted_with_cmk(t) if {
	some sse in t.expressions.server_side_encryption
	sse.enabled.constant_value == true
	lib.has_cmk(sse.kms_key_arn)
}
