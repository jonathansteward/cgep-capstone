# METADATA
# title: CC7.2 - Multi-region CloudTrail with log-file validation
# description: The plan must contain an aws_cloudtrail, and every trail must be multi-region with log-file validation.
# custom:
#   framework: soc2
#   controls:
#     - "CC7.2"
#   severity: high
#   remediation: "Set is_multi_region_trail = true and enable_log_file_validation = true."
package compliance.soc2.cc7_2_cloudtrail

import data.soc2.lib
import rego.v1

deny contains msg if {
	count(lib.resources("aws_cloudtrail")) == 0
	msg := "[SOC2 CC7.2] no aws_cloudtrail defined; audit activity is not recorded."
}

deny contains msg if {
	some t in lib.resources("aws_cloudtrail")
	not t.expressions.is_multi_region_trail.constant_value == true
	msg := sprintf("[SOC2 CC7.2] %s: trail is not multi-region.", [lib.addr(t)])
}

deny contains msg if {
	some t in lib.resources("aws_cloudtrail")
	not t.expressions.enable_log_file_validation.constant_value == true
	msg := sprintf("[SOC2 CC7.2] %s: log-file validation is disabled.", [lib.addr(t)])
}
