package terraform.tags

import rego.v1

import data.terraform.helpers

required := {"project", "environment", "owner", "cost-center"}

# Only resources that expose a known `tags` object are checked; resources without a tags
# attribute (subnets, role assignments) and tags known-after-apply are skipped.
deny contains msg if {
	some r in helpers.planned
	tags := r.change.after.tags
	is_object(tags)
	missing := required - {k | some k, _ in tags}
	count(missing) > 0
	msg := sprintf("%s is missing required tags: %v", [r.address, sort(missing)])
}
