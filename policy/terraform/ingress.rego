package terraform.ingress

import rego.v1

import data.terraform.helpers

world := {"*", "Internet", "0.0.0.0/0", "::/0"}

# Azure NSG: only 443 may be allowed inbound from the internet.
deny contains msg if {
	some r in helpers.planned
	r.type == "azurerm_network_security_rule"
	a := r.change.after
	a.direction == "Inbound"
	a.access == "Allow"
	a.source_address_prefix in world
	a.destination_port_range != "443"
	msg := sprintf("%s allows inbound %s from the internet; only 443 is permitted", [r.address, a.destination_port_range])
}

# AWS SG rule resources.
deny contains msg if {
	some r in helpers.planned
	r.type == "aws_vpc_security_group_ingress_rule"
	a := r.change.after
	a.cidr_ipv4 == "0.0.0.0/0"
	a.from_port != 443
	msg := sprintf("%s allows inbound port %v from 0.0.0.0/0; only 443 is permitted", [r.address, a.from_port])
}

# AWS legacy inline ingress blocks.
deny contains msg if {
	some r in helpers.planned
	r.type == "aws_security_group"
	some rule in r.change.after.ingress
	"0.0.0.0/0" in rule.cidr_blocks
	rule.from_port != 443
	msg := sprintf("%s inline ingress allows port %v from 0.0.0.0/0", [r.address, rule.from_port])
}
