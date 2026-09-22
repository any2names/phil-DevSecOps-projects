locals {
  name = "${var.project}-${var.environment}"
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = "vpc-${local.name}" })
}

# Adopt the VPC default security group and strip every rule so nothing can use it by accident.
resource "aws_default_security_group" "locked" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "default-locked-${local.name}" })
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.cidr, 8, 1)
  map_public_ip_on_launch = false # public IP is attached explicitly by the compute module
  tags                    = merge(var.tags, { Name = "snet-${local.name}-app" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "igw-${local.name}" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = merge(var.tags, { Name = "rt-${local.name}-public" })
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "app" {
  # checkov:skip=CKV2_AWS_5: attached to the instance by modules/compute/aws (cross-module; checkov cannot see it)
  name        = "${local.name}-app"
  description = "App VM: HTTPS from internet, SSH from admin CIDRs"
  vpc_id      = aws_vpc.this.id
  tags        = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS from internet"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
  tags              = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  for_each          = toset(var.allowed_ssh_cidrs)
  security_group_id = aws_security_group.app.id
  description       = "SSH from admin CIDR"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = each.value
  tags              = var.tags
}

# Egress is limited to what the host needs: HTTPS (secret store, apt), HTTP (apt mirrors),
# DNS and NTP. Any-destination is unavoidable for package mirrors and cloud APIs.
locals {
  egress = {
    https = { protocol = "tcp", port = 443, description = "HTTPS: secret store, apt, ACME" }
    http  = { protocol = "tcp", port = 80, description = "HTTP: apt mirrors" }
    dns   = { protocol = "udp", port = 53, description = "DNS" }
    ntp   = { protocol = "udp", port = 123, description = "NTP (chrony)" }
  }
}

resource "aws_vpc_security_group_egress_rule" "allowed" {
  #trivy:ignore:AVD-AWS-0104 destination cannot be narrowed for public mirrors/APIs; ports are
  for_each          = local.egress
  security_group_id = aws_security_group.app.id
  description       = each.value.description
  ip_protocol       = each.value.protocol
  from_port         = each.value.port
  to_port           = each.value.port
  cidr_ipv4         = "0.0.0.0/0"
  tags              = var.tags
}

# --- VPC flow logs → CloudWatch, KMS encrypted ---

resource "aws_kms_key" "logs" {
  # checkov:skip=CKV2_AWS_64: default key policy (account root only) is intended; an explicit policy needs the account id, unavailable in hermetic plans (ADR-0007)
  description             = "Flow log encryption for ${local.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/vpc/${local.name}/flow-logs"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logs.arn
  tags              = var.tags
}

locals {
  flow_assume = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
  flow_write = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow.arn}:*"
    }]
  })
}

resource "aws_iam_role" "flow" {
  name               = "role-${local.name}-flow-logs"
  assume_role_policy = local.flow_assume
  tags               = var.tags
}

#tfsec:ignore:aws-iam-no-policy-wildcards CloudWatch log streams live under "<log-group-arn>:*"; the group itself is exact
resource "aws_iam_role_policy" "flow" {
  name   = "flow-logs-write"
  role   = aws_iam_role.flow.id
  policy = local.flow_write
}

resource "aws_flow_log" "this" {
  vpc_id          = aws_vpc.this.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow.arn
  log_destination = aws_cloudwatch_log_group.flow.arn
  tags            = var.tags
}
