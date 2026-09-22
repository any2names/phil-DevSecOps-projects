# Root Terragrunt config. Each unit under envs/<env>/<cloud> includes this file.
# The unit path encodes environment and cloud, so units only declare inputs.

locals {
  path_parts   = split("/", path_relative_to_include())
  environment  = local.path_parts[1]
  cloud        = local.path_parts[2]
  backend_mode = get_env("TG_BACKEND", "local") # local | remote
  state_key    = "${local.environment}/${local.cloud}/terraform.tfstate"

  backend_configs = {
    local = {
      backend = "local"
      config  = { path = "${get_terragrunt_dir()}/.terragrunt-cache/terraform.tfstate" }
    }
    "remote-azure" = {
      backend = "azurerm"
      config = {
        resource_group_name  = "rg-tfstate-placeholder"
        storage_account_name = "tfstateplaceholder"
        container_name       = "tfstate"
        key                  = local.state_key
        use_oidc             = true
      }
    }
    "remote-aws" = {
      backend = "s3"
      config = {
        bucket         = "tfstate-placeholder"
        key            = local.state_key
        region         = "us-east-1"
        encrypt        = true
        dynamodb_table = "tfstate-placeholder-lock"
      }
    }
  }
  backend_key = local.backend_mode == "remote" ? "remote-${local.cloud}" : "local"
  backend     = lookup(local.backend_configs, local.backend_key)

  azure_provider = <<-EOT
    provider "azurerm" {
      features {}
      resource_provider_registrations = "none"
      subscription_id                 = "${get_env("ARM_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000000")}"
    }
  EOT

  aws_provider = <<-EOT
    provider "aws" {
      region                      = "${get_env("AWS_REGION", "us-east-1")}"
      skip_credentials_validation = true
      skip_requesting_account_id  = true
      skip_metadata_api_check     = true
      skip_region_validation      = true
    }
  EOT
}

terraform {
  # The double slash makes Terragrunt copy all of infra/ into the cache and run in the stack
  # subfolder, so the stacks' relative module paths (../../modules/...) and the secrets module's
  # relative ARM path keep working.
  source = "${get_parent_terragrunt_dir()}//terraform/stacks/${local.cloud}"
}

remote_state {
  backend = local.backend.backend
  config  = local.backend.config
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
}

generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = local.cloud == "azure" ? local.azure_provider : local.aws_provider
}

inputs = {
  project     = "sap"
  environment = local.environment
  tags = {
    project     = "sap"
    environment = local.environment
    owner       = "platform-team"
    cost-center = "engineering"
    managed-by  = "terragrunt"
  }
}
