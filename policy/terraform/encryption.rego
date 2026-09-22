package terraform.encryption

import rego.v1

import data.terraform.helpers

deny contains msg if {
	some r in helpers.planned
	r.type == "azurerm_linux_virtual_machine"
	r.change.after.encryption_at_host_enabled != true
	msg := sprintf("%s must set encryption_at_host_enabled = true", [r.address])
}

deny contains msg if {
	some r in helpers.planned
	r.type == "aws_instance"
	some disk in r.change.after.root_block_device
	disk.encrypted != true
	msg := sprintf("%s root volume must be encrypted", [r.address])
}

deny contains msg if {
	some r in helpers.planned
	r.type == "aws_secretsmanager_secret"
	helpers.missing(r, "kms_key_id")
	msg := sprintf("%s must use a customer-managed KMS key", [r.address])
}

deny contains msg if {
	some r in helpers.planned
	r.type == "aws_cloudwatch_log_group"
	helpers.missing(r, "kms_key_id")
	msg := sprintf("%s must be KMS encrypted", [r.address])
}

deny contains msg if {
	some r in helpers.planned
	r.type == "aws_kms_key"
	r.change.after.enable_key_rotation != true
	msg := sprintf("%s must enable key rotation", [r.address])
}
