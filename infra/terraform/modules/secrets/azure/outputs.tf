output "secret_store_id" {
  value = local.arm_outputs.keyVaultId.value
}

output "secret_store_uri" {
  value = local.arm_outputs.keyVaultUri.value
}
