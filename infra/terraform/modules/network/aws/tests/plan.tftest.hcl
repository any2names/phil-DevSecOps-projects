mock_provider "aws" {}

variables {
  project           = "sap"
  environment       = "dev"
  region            = "us-east-1"
  cidr              = "10.20.0.0/16"
  allowed_ssh_cidrs = ["203.0.113.0/24", "198.51.100.0/24"]
  tags              = { project = "sap", environment = "dev", owner = "platform", cost-center = "eng" }
}

run "ingress_rules" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_ingress_rule.https.from_port == 443 && aws_vpc_security_group_ingress_rule.https.cidr_ipv4 == "0.0.0.0/0"
    error_message = "HTTPS must be open on 443."
  }
  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.ssh) == 2
    error_message = "One SSH rule per allowed CIDR."
  }
  assert {
    condition     = aws_cloudwatch_log_group.flow.retention_in_days == 90 && aws_flow_log.this.traffic_type == "ALL"
    error_message = "Flow logs must capture ALL traffic for 90 days."
  }
  assert {
    condition     = aws_kms_key.logs.enable_key_rotation == true
    error_message = "Log KMS key must rotate."
  }
}

run "rejects_world_open_ssh" {
  command = plan
  variables {
    allowed_ssh_cidrs = ["::/0"]
  }
  expect_failures = [var.allowed_ssh_cidrs]
}
