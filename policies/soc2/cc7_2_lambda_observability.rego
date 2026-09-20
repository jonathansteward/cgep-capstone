# METADATA
# title: CC7.2 - Lambda functions have X-Ray tracing and a dead-letter queue
# description: Every aws_lambda_function needs tracing_config mode Active and a dead_letter_config target.
# custom:
#   framework: soc2
#   controls:
#     - "CC7.2"
#   gaps:
#     - "GAP-06"
#   severity: medium
#   remediation: "Add tracing_config { mode = \"Active\" } and dead_letter_config { target_arn = aws_sqs_queue.<dlq>.arn }."
package compliance.soc2.cc7_2_lambda_observability

import data.soc2.lib
import rego.v1

deny contains msg if {
	some f in lib.resources("aws_lambda_function")
	not traced(f)
	msg := sprintf("[SOC2 CC7.2] %s: X-Ray tracing is not Active (GAP-06).", [lib.addr(f)])
}

deny contains msg if {
	some f in lib.resources("aws_lambda_function")
	not has_dlq(f)
	msg := sprintf("[SOC2 CC7.2] %s: no dead_letter_config (GAP-06).", [lib.addr(f)])
}

traced(f) if {
	some t in f.expressions.tracing_config
	t.mode.constant_value == "Active"
}

has_dlq(f) if {
	some d in f.expressions.dead_letter_config
	lib.has_cmk(d.target_arn)
}
