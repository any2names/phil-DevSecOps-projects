module "network" {
  source            = "../../modules/network/aws"
  project           = var.project
  environment       = var.environment
  region            = var.region
  cidr              = var.cidr
  allowed_ssh_cidrs = var.allowed_ssh_cidrs
  tags              = var.tags
}

module "compute" {
  source            = "../../modules/compute/aws"
  project           = var.project
  environment       = var.environment
  region            = var.region
  subnet_id         = module.network.subnet_id
  security_group_id = module.network.security_group_id
  instance_size     = var.instance_size
  ssh_public_key    = var.ssh_public_key
  ami_id            = var.ami_id
  tags              = var.tags
}

module "secrets" {
  source        = "../../modules/secrets/aws"
  project       = var.project
  environment   = var.environment
  region        = var.region
  iam_role_name = module.compute.iam_role_name
  tags          = var.tags
}
