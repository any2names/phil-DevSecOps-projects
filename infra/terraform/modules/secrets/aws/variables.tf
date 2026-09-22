variable "project" { type = string }
variable "environment" { type = string }
variable "region" { type = string }

variable "iam_role_name" {
  description = "Name of the VM instance role that may read the secret."
  type        = string
}

variable "tags" { type = map(string) }
