package terraform.instances

import rego.v1

import data.terraform.helpers

allowed := {
	"dev": {"Standard_B2s", "Standard_B2ms", "t3.micro", "t3.small"},
	"prod": {"Standard_D2s_v5", "Standard_D4s_v5", "t3.medium", "m6i.large"},
}

size(r) := r.change.after.size if r.type == "azurerm_linux_virtual_machine"

size(r) := r.change.after.instance_type if r.type == "aws_instance"

deny contains msg if {
	some r in helpers.planned
	s := size(r)
	not s in allowed[helpers.environment]
	msg := sprintf("%s size %q is not in the %s allow-list %v", [r.address, s, helpers.environment, sort(allowed[helpers.environment])])
}
