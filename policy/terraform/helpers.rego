package terraform.helpers

import rego.v1

# Resources that will exist after apply (created or updated), with their planned attributes.
planned contains r if {
	some r in input.resource_changes
	some action in r.change.actions
	action in {"create", "update"}
}

# Resources the plan would destroy (including replacements).
destroyed contains r if {
	some r in input.resource_changes
	"delete" in r.change.actions
}

environment := input.variables.environment.value

is_prod if environment == "prod"

# True when the attribute is neither set (non-null) nor "known after apply".
missing(r, attr) if {
	not has_value(r.change.after, attr)
	not r.change.after_unknown[attr]
}

has_value(obj, attr) if obj[attr] != null
