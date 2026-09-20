# METADATA
# title: CC6.7 - S3 buckets deny non-TLS requests
# description: Every aws_s3_bucket needs a bucket policy with a Deny statement on aws:SecureTransport = false.
# custom:
#   framework: soc2
#   controls:
#     - "CC6.7"
#   gaps:
#     - "GAP-03"
#   severity: high
#   remediation: "Add aws_s3_bucket_policy whose aws_iam_policy_document denies s3:* when aws:SecureTransport is false."
package compliance.soc2.cc6_7_s3_tls

import data.soc2.lib
import rego.v1

deny contains msg if {
	some b in lib.resources("aws_s3_bucket")
	not enforces_tls(b)
	msg := sprintf("[SOC2 CC6.7] %s: no bucket policy denying aws:SecureTransport=false (GAP-03).", [lib.addr(b)])
}

enforces_tls(b) if {
	some p in lib.resources("aws_s3_bucket_policy")
	lib.refers_to(p.expressions.bucket, lib.addr(b))
	doc := lib.policy_doc(p.expressions.policy)
	some s in doc.expressions.statement
	s.effect.constant_value == "Deny"
	some c in s.condition
	c.variable.constant_value == "aws:SecureTransport"
	"false" in c.values.constant_value
}
