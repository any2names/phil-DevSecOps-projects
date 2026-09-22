package terraform.encryption_test

import rego.v1

import data.terraform.encryption

res(type, after, unknown) := {"resource_changes": [{"address": concat(".", [type, "x"]), "type": type, "change": {"actions": ["create"], "after": after, "after_unknown": unknown}}]}

test_vm_encrypted_ok if {
	count(encryption.deny) == 0 with input as res("azurerm_linux_virtual_machine", {"encryption_at_host_enabled": true}, {})
}

test_vm_unencrypted_denied if {
	count(encryption.deny) == 1 with input as res("azurerm_linux_virtual_machine", {"encryption_at_host_enabled": false}, {})
}

test_instance_root_unencrypted_denied if {
	count(encryption.deny) == 1 with input as res("aws_instance", {"root_block_device": [{"encrypted": false}]}, {})
}

test_secret_kms_known_after_apply_ok if {
	count(encryption.deny) == 0 with input as res("aws_secretsmanager_secret", {}, {"kms_key_id": true})
}

test_secret_no_kms_denied if {
	count(encryption.deny) == 1 with input as res("aws_secretsmanager_secret", {"kms_key_id": null}, {})
}

test_kms_rotation_denied if {
	count(encryption.deny) == 1 with input as res("aws_kms_key", {"enable_key_rotation": false}, {})
}
