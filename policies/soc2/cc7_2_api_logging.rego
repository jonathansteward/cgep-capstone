# METADATA
# title: CC7.2 - API Gateway stages have access logging and throttling
# description: Every aws_apigatewayv2_stage needs access_log_settings and default_route_settings with a rate limit.
# custom:
#   framework: soc2
#   controls:
#     - "CC7.2"
#   gaps:
#     - "GAP-08"
#   severity: medium
#   remediation: "Add access_log_settings pointing at a CloudWatch log group and default_route_settings throttling limits."
package compliance.soc2.cc7_2_api_logging

import data.soc2.lib
import rego.v1

deny contains msg if {
	some s in lib.resources("aws_apigatewayv2_stage")
	not logs(s)
	msg := sprintf("[SOC2 CC7.2] %s: no access_log_settings destination (GAP-08).", [lib.addr(s)])
}

deny contains msg if {
	some s in lib.resources("aws_apigatewayv2_stage")
	not throttled(s)
	msg := sprintf("[SOC2 CC7.2] %s: no throttling_rate_limit in default_route_settings (GAP-08).", [lib.addr(s)])
}

logs(s) if {
	some l in s.expressions.access_log_settings
	lib.has_cmk(l.destination_arn)
}

throttled(s) if {
	some d in s.expressions.default_route_settings
	d.throttling_rate_limit
}
