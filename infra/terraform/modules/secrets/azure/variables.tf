variable "project" { type = string }
variable "environment" { type = string }
variable "region" { type = string }
variable "resource_group_name" { type = string }

variable "principal_id" {
  description = "Principal ID of the VM's managed identity that may read secrets."
  type        = string
}

variable "tags" { type = map(string) }
