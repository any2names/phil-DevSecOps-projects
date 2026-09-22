locals {
  name       = "${var.project}-${var.environment}"
  admin_user = "platform"
}

resource "azurerm_user_assigned_identity" "vm" {
  name                = "id-${local.name}-vm"
  location            = var.region
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_public_ip" "vm" {
  name                = "pip-${local.name}-vm"
  location            = var.region
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "vm" {
  name                = "nic-${local.name}-vm"
  location            = var.region
  resource_group_name = var.resource_group_name
  tags                = var.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm.id
  }
}

resource "azurerm_linux_virtual_machine" "this" {
  name                            = "vm-${local.name}-app"
  location                        = var.region
  resource_group_name             = var.resource_group_name
  size                            = var.instance_size
  admin_username                  = local.admin_user
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.vm.id]
  encryption_at_host_enabled      = true
  allow_extension_operations      = true # Ansible installs the Azure Monitor agent extension
  tags                            = var.tags

  admin_ssh_key {
    username   = local.admin_user
    public_key = var.ssh_public_key
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.vm.id]
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  boot_diagnostics {} # managed storage account
}
