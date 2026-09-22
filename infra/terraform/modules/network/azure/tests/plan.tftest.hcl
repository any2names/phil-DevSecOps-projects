mock_provider "azurerm" {}

variables {
  project             = "sap"
  environment         = "dev"
  region              = "eastus"
  resource_group_name = "rg-sap-dev"
  cidr                = "10.10.0.0/16"
  allowed_ssh_cidrs   = ["203.0.113.0/24"]
  tags                = { project = "sap", environment = "dev", owner = "platform", cost-center = "eng" }
}

run "https_is_the_only_internet_ingress" {
  command = plan

  assert {
    condition     = azurerm_network_security_rule.https_in.destination_port_range == "443" && azurerm_network_security_rule.https_in.source_address_prefix == "Internet"
    error_message = "HTTPS rule must allow 443 from Internet only."
  }
  assert {
    condition     = azurerm_network_security_rule.ssh_in.source_address_prefixes == toset(["203.0.113.0/24"])
    error_message = "SSH must be restricted to allowed_ssh_cidrs."
  }
  assert {
    condition     = azurerm_network_security_rule.deny_all_in.access == "Deny" && azurerm_network_security_rule.deny_all_in.priority == 4000
    error_message = "A catch-all deny rule must exist."
  }
  assert {
    condition     = azurerm_subnet.this.address_prefixes[0] == "10.10.1.0/24"
    error_message = "App subnet must be the second /24 of the VNet."
  }
}

run "rejects_world_open_ssh" {
  command = plan
  variables {
    allowed_ssh_cidrs = ["0.0.0.0/0"]
  }
  expect_failures = [var.allowed_ssh_cidrs]
}

run "rejects_unknown_environment" {
  command = plan
  variables {
    environment = "staging"
  }
  expect_failures = [var.environment]
}
