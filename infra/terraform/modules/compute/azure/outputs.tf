output "vm_public_ip" {
  value = azurerm_public_ip.vm.ip_address
}

output "vm_private_ip" {
  value = azurerm_network_interface.vm.private_ip_address
}

output "identity_id" {
  value = azurerm_user_assigned_identity.vm.id
}

output "identity_principal_id" {
  value = azurerm_user_assigned_identity.vm.principal_id
}
