include "root" {
  path = find_in_parent_folders("terragrunt.hcl")
}

inputs = {
  region            = "us-east-2"
  cidr              = "10.21.0.0/16"
  allowed_ssh_cidrs = ["203.0.113.0/24"] # replace with your admin egress CIDR
  instance_size     = "t3.medium"
  ami_id            = "ami-0123456789abcdef0" # placeholder: resolve per docs/runbooks/deploy.md
  ssh_public_key    = get_env("PLATFORM_SSH_PUBLIC_KEY", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFkcx5iBmJDJIHeaGZWntScBb/rXtTto7TlbHigClFU test-placeholder-not-for-real-use")
}
