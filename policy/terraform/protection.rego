package terraform.protection

import rego.v1

import data.terraform.helpers

# Stateful resources that must never be destroyed by an automated prod plan.
stateful := {"aws_kms_key", "aws_secretsmanager_secret", "azurerm_resource_group_template_deployment", "azurerm_resource_group"}

deny contains msg if {
	helpers.is_prod
	some r in helpers.destroyed
	r.type in stateful
	msg := sprintf("prod plan would destroy stateful resource %s; requires a manual break-glass apply", [r.address])
}

deny contains msg if {
	some r in helpers.planned
	r.type == "azurerm_resource_group_template_deployment"
	r.change.after.deployment_mode != "Incremental"
	msg := sprintf("%s must use Incremental mode (Complete deletes unmanaged resources)", [r.address])
}

deny contains msg if {
	helpers.is_prod
	some r in helpers.planned
	r.type == "aws_secretsmanager_secret"
	r.change.after.recovery_window_in_days < 30
	msg := sprintf("%s recovery window must be >= 30 days in prod", [r.address])
}

deny contains msg if {
	helpers.is_prod
	some r in helpers.planned
	r.type == "aws_kms_key"
	r.change.after.deletion_window_in_days < 30
	msg := sprintf("%s deletion window must be >= 30 days in prod", [r.address])
}
