variable "project" {
  description = "Short project slug used in resource names."
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev|prod)."
  type        = string
  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "environment must be dev or prod."
  }
}

variable "region" {
  description = "Azure location."
  type        = string
}

variable "resource_group_name" {
  description = "Existing resource group to deploy into."
  type        = string
}

variable "cidr" {
  description = "VNet address space."
  type        = string
  validation {
    condition     = can(cidrhost(var.cidr, 0))
    error_message = "cidr must be a valid IPv4 CIDR."
  }
}

variable "allowed_ssh_cidrs" {
  description = "CIDRs allowed to reach SSH. Never the whole internet."
  type        = list(string)
  validation {
    condition     = !contains(var.allowed_ssh_cidrs, "0.0.0.0/0") && !contains(var.allowed_ssh_cidrs, "::/0")
    error_message = "allowed_ssh_cidrs must not contain 0.0.0.0/0 or ::/0."
  }
}

variable "tags" {
  description = "Tags applied to every resource. project/environment/owner/cost-center are required by policy."
  type        = map(string)
}
