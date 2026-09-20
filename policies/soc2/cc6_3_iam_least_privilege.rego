# METADATA
# title: CC6.3 - No wildcard actions in IAM policies
# description: IAM role policies built from aws_iam_policy_document must not Allow "*" or "service:*" actions; AdministratorAccess must not be attached.
# custom:
#   framework: soc2
#   controls:
#     - "CC6.3"
#   gaps:
#     - "GAP-07"
#   severity: high
#   remediation: "List the specific API actions the workload needs (e.g. dynamodb:PutItem)."
package compliance.soc2.cc6_3_iam_least_privilege

import data.soc2.lib
import rego.v1

policy_types := {"aws_iam_role_policy", "aws_iam_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

deny contains msg if {
	some t in policy_types
	some p in lib.resources(t)
	doc := lib.policy_doc(p.expressions.policy)
	some s in doc.expressions.statement
	s.effect.constant_value == "Allow"
	some action in s.actions.constant_value
	wildcard(action)
	msg := sprintf("[SOC2 CC6.3] %s: statement allows wildcard action %q (GAP-07). Grant specific actions.", [lib.addr(p), action])
}

deny contains msg if {
	some a in lib.resources("aws_iam_role_policy_attachment")
	endswith(a.expressions.policy_arn.constant_value, "/AdministratorAccess")
	msg := sprintf("[SOC2 CC6.3] %s: attaches AdministratorAccess.", [lib.addr(a)])
}

wildcard(action) if action == "*"

wildcard(action) if endswith(action, ":*")
