mock_provider "aws" {}

variables {
  project           = "sap"
  environment       = "dev"
  region            = "us-east-1"
  subnet_id         = "subnet-0123456789abcdef0"
  security_group_id = "sg-0123456789abcdef0"
  ami_id            = "ami-0123456789abcdef0"
  ssh_public_key    = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFkcx5iBmJDJIHeaGZWntScBb/rXtTto7TlbHigClFU test-placeholder-not-for-real-use"
  tags              = { project = "sap", environment = "dev", owner = "platform", cost-center = "eng" }
}

run "hardened_instance" {
  command = plan

  assert {
    condition     = aws_instance.this.metadata_options[0].http_tokens == "required"
    error_message = "IMDSv2 must be required."
  }
  assert {
    condition     = aws_instance.this.root_block_device[0].encrypted == true
    error_message = "Root volume must be encrypted."
  }
  assert {
    condition     = aws_instance.this.monitoring == true && aws_instance.this.ebs_optimized == true
    error_message = "Detailed monitoring and EBS optimisation must be on."
  }
}

run "rejects_bad_ami" {
  command = plan
  variables {
    ami_id = "ami-123"
  }
  expect_failures = [var.ami_id]
}
