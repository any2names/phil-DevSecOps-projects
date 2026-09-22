package terraform.protection_test

import rego.v1

import data.terraform.protection

plan(env, changes) := {"variables": {"environment": {"value": env}}, "resource_changes": changes}

kms_delete := [{"address": "aws_kms_key.x", "type": "aws_kms_key", "change": {"actions": ["delete"], "before": {}}}]

test_prod_kms_destroy_denied if {
	count(protection.deny) == 1 with input as plan("prod", kms_delete)
}

test_dev_kms_destroy_ok if {
	count(protection.deny) == 0 with input as plan("dev", kms_delete)
}

test_complete_mode_denied if {
	count(protection.deny) == 1 with input as plan("dev", [{"address": "azurerm_resource_group_template_deployment.x", "type": "azurerm_resource_group_template_deployment", "change": {"actions": ["create"], "after": {"deployment_mode": "Complete"}}}])
}

test_prod_short_recovery_denied if {
	count(protection.deny) == 1 with input as plan("prod", [{"address": "aws_secretsmanager_secret.x", "type": "aws_secretsmanager_secret", "change": {"actions": ["create"], "after": {"recovery_window_in_days": 7}}}])
}
