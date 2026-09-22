package terraform.instances_test

import rego.v1

import data.terraform.instances

plan(env, type, attr, val) := {
	"variables": {"environment": {"value": env}},
	"resource_changes": [{"address": concat(".", [type, "x"]), "type": type, "change": {"actions": ["create"], "after": {attr: val}}}],
}

test_dev_small_ok if {
	count(instances.deny) == 0 with input as plan("dev", "aws_instance", "instance_type", "t3.small")
}

test_dev_large_denied if {
	count(instances.deny) == 1 with input as plan("dev", "aws_instance", "instance_type", "m6i.large")
}

test_prod_burstable_denied if {
	count(instances.deny) == 1 with input as plan("prod", "azurerm_linux_virtual_machine", "size", "Standard_B2s")
}

test_prod_d_series_ok if {
	count(instances.deny) == 0 with input as plan("prod", "azurerm_linux_virtual_machine", "size", "Standard_D2s_v5")
}
