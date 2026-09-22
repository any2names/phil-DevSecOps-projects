mock_provider "azurerm" {}

variables {
  project             = "sap"
  environment         = "dev"
  region              = "eastus"
  resource_group_name = "rg-sap-dev"
  subnet_id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sap-dev/providers/Microsoft.Network/virtualNetworks/vnet/subnets/snet"
  ssh_public_key      = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFkcx5iBmJDJIHeaGZWntScBb/rXtTto7TlbHigClFU test-placeholder-not-for-real-use"
  tags                = { project = "sap", environment = "dev", owner = "platform", cost-center = "eng" }
}

run "hardened_vm" {
  command = plan

  assert {
    condition     = azurerm_linux_virtual_machine.this.disable_password_authentication == true
    error_message = "Password auth must be disabled."
  }
  assert {
    condition     = azurerm_linux_virtual_machine.this.encryption_at_host_enabled == true
    error_message = "Encryption at host must be enabled."
  }
  assert {
    condition     = azurerm_linux_virtual_machine.this.identity[0].type == "UserAssigned"
    error_message = "VM must use a user-assigned managed identity."
  }
  assert {
    condition     = azurerm_public_ip.vm.sku == "Standard"
    error_message = "Public IP must be Standard SKU (zone-redundant, secure by default)."
  }
}

run "rejects_bad_key" {
  command = plan
  variables {
    ssh_public_key = "not-a-key"
  }
  expect_failures = [var.ssh_public_key]
}
