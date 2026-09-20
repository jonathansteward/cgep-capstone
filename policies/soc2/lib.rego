# Shared helpers for the SOC 2 policy suite. Policies read the *configuration*
# section of `terraform show -json` because values wired by reference
# (e.g. a KMS key ARN) are unknown at plan time.
package soc2.lib

import rego.v1

# Managed resources of a type in the root module.
resources(type) := {r |
	some r in input.configuration.root_module.resources
	r.mode == "managed"
	r.type == type
}

# Data sources of a type in the root module.
data_sources(type) := {r |
	some r in input.configuration.root_module.resources
	r.mode == "data"
	r.type == type
}

addr(r) := sprintf("%s.%s", [r.type, r.name])

# True when the expression references the resource at `a` (or an attribute of it).
refers_to(expr, a) if {
	some ref in expr.references
	ref == a
}

refers_to(expr, a) if {
	some ref in expr.references
	startswith(ref, concat("", [a, "."]))
}

# True when an expression names a customer key: any reference, or a constant
# that is not an AWS-managed alias.
has_cmk(expr) if count(expr.references) > 0

has_cmk(expr) if {
	is_string(expr.constant_value)
	expr.constant_value != ""
	not startswith(expr.constant_value, "alias/aws/")
}

# The aws_iam_policy_document data source that an expression's `.json` refers to.
policy_doc(expr) := d if {
	some d in data_sources("aws_iam_policy_document")
	some ref in expr.references
	ref == sprintf("data.aws_iam_policy_document.%s.json", [d.name])
}
