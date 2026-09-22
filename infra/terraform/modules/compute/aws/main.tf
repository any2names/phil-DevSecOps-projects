locals {
  name = "${var.project}-${var.environment}"
  assume_ec2 = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role" "vm" {
  name               = "role-${local.name}-vm"
  assume_role_policy = local.assume_ec2
  tags               = var.tags
}

resource "aws_iam_instance_profile" "vm" {
  name = "profile-${local.name}-vm"
  role = aws_iam_role.vm.name
  tags = var.tags
}

resource "aws_key_pair" "admin" {
  key_name   = "key-${local.name}-admin"
  public_key = var.ssh_public_key
  tags       = var.tags
}

resource "aws_kms_key" "disk" {
  # checkov:skip=CKV2_AWS_64: default key policy (account root only) is intended; see modules/network/aws
  description             = "Root volume encryption for ${local.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags
}

resource "aws_eip" "vm" {
  domain = "vpc"
  tags   = merge(var.tags, { Name = "eip-${local.name}-vm" })
}

resource "aws_instance" "this" {
  ami                         = var.ami_id
  instance_type               = var.instance_size
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [var.security_group_id]
  iam_instance_profile        = aws_iam_instance_profile.vm.name
  key_name                    = aws_key_pair.admin.key_name
  associate_public_ip_address = false
  monitoring                  = true
  ebs_optimized               = true
  tags                        = merge(var.tags, { Name = "vm-${local.name}-app" })

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
    kms_key_id  = aws_kms_key.disk.arn
  }
}

resource "aws_eip_association" "vm" {
  instance_id   = aws_instance.this.id
  allocation_id = aws_eip.vm.id
}
