include "root" {
  path = find_in_parent_folders("terragrunt.hcl")
}

inputs = {
  region            = "eastus2"
  cidr              = "10.11.0.0/16"
  allowed_ssh_cidrs = ["203.0.113.0/24"] # replace with your admin egress CIDR
  instance_size     = "Standard_D2s_v5"

  ssh_public_key = get_env("PLATFORM_SSH_PUBLIC_KEY", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFkcx5iBmJDJIHeaGZWntScBb/rXtTto7TlbHigClFU test-placeholder-not-for-real-use")
}
