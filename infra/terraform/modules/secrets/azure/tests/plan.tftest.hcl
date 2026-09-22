mock_provider "azurerm" {}

variables {
  project             = "sap"
  environment         = "dev"
  region              = "eastus"
  resource_group_name = "rg-sap-dev"
  principal_id        = "00000000-0000-0000-0000-000000000000"
  tags                = { project = "sap", environment = "dev", owner = "platform", cost-center = "eng" }
}

run "arm_wrapped_keyvault" {
  command = plan

  assert {
    condition     = azurerm_resource_group_template_deployment.keyvault.deployment_mode == "Incremental"
    error_message = "ARM deployment must be Incremental (never Complete — it would delete the RG contents)."
  }
  assert {
    condition     = length(jsondecode(azurerm_resource_group_template_deployment.keyvault.parameters_content).keyVaultName.value) <= 24 && startswith(jsondecode(azurerm_resource_group_template_deployment.keyvault.parameters_content).keyVaultName.value, "kv-sap-dev-")
    error_message = "Key Vault name must be ≤ 24 chars and prefixed."
  }
  assert {
    condition     = jsondecode(azurerm_resource_group_template_deployment.keyvault.template_content).resources[0].properties.enablePurgeProtection == true
    error_message = "ARM template must enable purge protection."
  }
  assert {
    condition     = jsondecode(azurerm_resource_group_template_deployment.keyvault.template_content).resources[0].properties.publicNetworkAccess == "Disabled"
    error_message = "ARM template must disable public network access."
  }
  assert {
    condition     = azurerm_role_assignment.vm_reads_secrets.role_definition_name == "Key Vault Secrets User"
    error_message = "VM identity must get read-only secret access."
  }
}
