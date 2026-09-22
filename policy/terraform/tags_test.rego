package terraform.tags_test

import rego.v1

import data.terraform.tags

res(t) := {"resource_changes": [{"address": "aws_vpc.x", "type": "aws_vpc", "change": {"actions": ["create"], "after": {"tags": t}}}]}

test_all_tags_ok if {
	count(tags.deny) == 0 with input as res({"project": "p", "environment": "dev", "owner": "o", "cost-center": "c", "extra": "e"})
}

test_missing_owner_denied if {
	msgs := tags.deny with input as res({"project": "p", "environment": "dev", "cost-center": "c"})
	count(msgs) == 1
	some m in msgs
	contains(m, "owner")
}

test_untagged_resource_type_skipped if {
	count(tags.deny) == 0 with input as {"resource_changes": [{"address": "azurerm_subnet.x", "type": "azurerm_subnet", "change": {"actions": ["create"], "after": {"name": "s"}}}]}
}
