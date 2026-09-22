resource "azurerm_resource_group" "this" {
  name     = "rg-${var.project}-${var.environment}"
  location = var.region
  tags     = var.tags
}

module "network" {
  source              = "../../modules/network/azure"
  project             = var.project
  environment         = var.environment
  region              = var.region
  resource_group_name = azurerm_resource_group.this.name
  cidr                = var.cidr
  allowed_ssh_cidrs   = var.allowed_ssh_cidrs
  tags                = var.tags
}

module "compute" {
  source              = "../../modules/compute/azure"
  project             = var.project
  environment         = var.environment
  region              = var.region
  resource_group_name = azurerm_resource_group.this.name
  subnet_id           = module.network.subnet_id
  instance_size       = var.instance_size
  ssh_public_key      = var.ssh_public_key
  tags                = var.tags
}

module "secrets" {
  source              = "../../modules/secrets/azure"
  project             = var.project
  environment         = var.environment
  region              = var.region
  resource_group_name = azurerm_resource_group.this.name
  principal_id        = module.compute.identity_principal_id
  tags                = var.tags
}
