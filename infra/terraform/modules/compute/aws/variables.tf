variable "project" { type = string }
variable "environment" { type = string }
variable "region" { type = string }
variable "subnet_id" { type = string }
variable "security_group_id" { type = string }

variable "instance_size" {
  description = "Instance type. The allow-list per environment is enforced by OPA policy."
  type        = string
  default     = "t3.small"
}

variable "ami_id" {
  description = "Ubuntu 22.04 AMI for the region. Replace the placeholder per docs/runbooks/deploy.md."
  type        = string
  validation {
    condition     = can(regex("^ami-[0-9a-f]{17}$", var.ami_id))
    error_message = "ami_id must look like ami-xxxxxxxxxxxxxxxxx."
  }
}

variable "ssh_public_key" {
  description = "OpenSSH public key for the platform admin user."
  type        = string
  validation {
    condition     = can(regex("^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) ", var.ssh_public_key))
    error_message = "ssh_public_key must be an OpenSSH public key."
  }
}

variable "tags" { type = map(string) }
