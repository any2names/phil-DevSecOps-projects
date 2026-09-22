locals {
  name = "${var.project}-${var.environment}"
  # Key Vault names are globally unique and ≤ 24 chars; a short hash of the RG keeps it stable.
  kv_name = substr("kv-${local.name}-${md5(var.resource_group_name)}", 0, 24)
}

resource "azurerm_resource_group_template_deployment" "keyvault" {
  name                = "kv-${local.name}"
  resource_group_name = var.resource_group_name
  deployment_mode     = "Incremental"
  template_content    = file("${path.module}/../../../../arm/keyvault.json")
  parameters_content = jsonencode({
    keyVaultName = { value = local.kv_name }
    location     = { value = var.region }
    tags         = { value = var.tags }
  })
  tags = var.tags
}

locals {
  arm_outputs = jsondecode(azurerm_resource_group_template_deployment.keyvault.output_content)
}

resource "azurerm_role_assignment" "vm_reads_secrets" {
  scope                = local.arm_outputs.keyVaultId.value
  role_definition_name = "Key Vault Secrets User"
  principal_id         = var.principal_id
}
