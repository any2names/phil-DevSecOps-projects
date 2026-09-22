variable "project" { type = string }
variable "environment" { type = string }
variable "region" { type = string }
variable "resource_group_name" { type = string }
variable "subnet_id" { type = string }

variable "instance_size" {
  description = "VM size. The allow-list per environment is enforced by OPA policy."
  type        = string
  default     = "Standard_B2s"
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
