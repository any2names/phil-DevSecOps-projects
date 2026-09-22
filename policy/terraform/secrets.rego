package terraform.secrets

import rego.v1

import data.terraform.helpers

# Secret *values* never belong in IaC. These resource types carry values into state.
forbidden_types := {"aws_secretsmanager_secret_version", "azurerm_key_vault_secret"}

patterns := [
	`AKIA[0-9A-Z]{16}`,
	`-----BEGIN [A-Z ]*PRIVATE KEY-----`,
	`(?i)ghp_[A-Za-z0-9]{36}`,
	`(?i)xox[bap]-[0-9A-Za-z-]{10,}`,
]

deny contains msg if {
	some r in helpers.planned
	r.type in forbidden_types
	msg := sprintf("%s writes a secret value into Terraform state; use `platformctl secrets rotate --execute` instead", [r.address])
}

deny contains msg if {
	some r in helpers.planned
	walk(r.change.after, [path, value])
	is_string(value)
	some p in patterns
	regex.match(p, value)
	msg := sprintf("%s attribute %v looks like a credential", [r.address, concat(".", [sprintf("%v", [x]) | some x in path])])
}
