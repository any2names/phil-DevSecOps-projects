output "vm_public_ip" { value = module.compute.vm_public_ip }
output "vm_private_ip" { value = module.compute.vm_private_ip }
output "secret_store_id" { value = module.secrets.secret_store_id }
output "secret_store_uri" { value = module.secrets.secret_store_uri }
output "identity_id" { value = module.compute.identity_id }
