# METADATA
# title: A1.2 - S3 buckets have versioning enabled
# description: Every aws_s3_bucket needs an aws_s3_bucket_versioning resource with status Enabled so overwrites are recoverable.
# custom:
#   framework: soc2
#   controls:
#     - "A1.2"
#   gaps:
#     - "GAP-04"
#   severity: medium
#   remediation: "Add aws_s3_bucket_versioning with versioning_configuration { status = \"Enabled\" }."
package compliance.soc2.a1_2_s3_versioning

import data.soc2.lib
import rego.v1

deny contains msg if {
	some b in lib.resources("aws_s3_bucket")
	not versioned(b)
	msg := sprintf("[SOC2 A1.2] %s: versioning is not enabled (GAP-04).", [lib.addr(b)])
}

versioned(b) if {
	some v in lib.resources("aws_s3_bucket_versioning")
	lib.refers_to(v.expressions.bucket, lib.addr(b))
	some cfg in v.expressions.versioning_configuration
	cfg.status.constant_value == "Enabled"
}
