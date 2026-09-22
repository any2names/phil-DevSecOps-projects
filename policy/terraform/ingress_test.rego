package terraform.ingress_test

import rego.v1

import data.terraform.ingress

nsg(port, src) := {"resource_changes": [{
	"address": "azurerm_network_security_rule.x", "type": "azurerm_network_security_rule",
	"change": {"actions": ["create"], "after": {"direction": "Inbound", "access": "Allow", "source_address_prefix": src, "destination_port_range": port}},
}]}

sg(port, cidr) := {"resource_changes": [{
	"address": "aws_vpc_security_group_ingress_rule.x", "type": "aws_vpc_security_group_ingress_rule",
	"change": {"actions": ["create"], "after": {"cidr_ipv4": cidr, "from_port": port}},
}]}

test_azure_https_from_internet_ok if {
	count(ingress.deny) == 0 with input as nsg("443", "Internet")
}

test_azure_ssh_from_internet_denied if {
	count(ingress.deny) == 1 with input as nsg("22", "*")
}

test_azure_ssh_from_admin_cidr_ok if {
	count(ingress.deny) == 0 with input as nsg("22", "203.0.113.0/24")
}

test_aws_https_ok if {
	count(ingress.deny) == 0 with input as sg(443, "0.0.0.0/0")
}

test_aws_ssh_world_denied if {
	count(ingress.deny) == 1 with input as sg(22, "0.0.0.0/0")
}

test_deleted_resources_ignored if {
	count(ingress.deny) == 0 with input as {"resource_changes": [{
		"address": "a", "type": "aws_vpc_security_group_ingress_rule",
		"change": {"actions": ["delete"], "before": {"cidr_ipv4": "0.0.0.0/0", "from_port": 22}},
	}]}
}
