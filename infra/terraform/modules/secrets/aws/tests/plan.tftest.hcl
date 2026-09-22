mock_provider "aws" {}

variables {
  project       = "sap"
  environment   = "dev"
  region        = "us-east-1"
  iam_role_name = "role-sap-dev-vm"
  tags          = { project = "sap", environment = "dev", owner = "platform", cost-center = "eng" }
}

run "encrypted_secret_least_privilege" {
  command = plan

  assert {
    condition     = aws_kms_key.secrets.enable_key_rotation == true
    error_message = "Secrets KMS key must rotate."
  }
  assert {
    condition     = aws_secretsmanager_secret.app.recovery_window_in_days == 30
    error_message = "Accidental deletion must be recoverable for 30 days."
  }
  assert {
    condition     = aws_secretsmanager_secret.app.name == "sap-dev/app"
    error_message = "Secret name must follow <project>-<env>/app."
  }
}
