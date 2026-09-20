# METADATA
# title: CC6.6 - Lambda functions run inside a VPC
# description: Every aws_lambda_function needs a vpc_config with subnets and security groups.
# custom:
#   framework: soc2
#   controls:
#     - "CC6.6"
#   gaps:
#     - "GAP-05"
#   severity: high
#   remediation: "Add vpc_config { subnet_ids = aws_subnet.private[*].id, security_group_ids = [...] }."
package compliance.soc2.cc6_6_lambda_vpc

import data.soc2.lib
import rego.v1

deny contains msg if {
	some f in lib.resources("aws_lambda_function")
	not in_vpc(f)
	msg := sprintf("[SOC2 CC6.6] %s: function is not attached to a VPC (GAP-05).", [lib.addr(f)])
}

in_vpc(f) if {
	some v in f.expressions.vpc_config
	count(v.subnet_ids.references) > 0
	count(v.security_group_ids.references) > 0
}
