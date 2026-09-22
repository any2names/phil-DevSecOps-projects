locals {
  name = "${var.project}-${var.environment}"
}

resource "aws_kms_key" "secrets" {
  # checkov:skip=CKV2_AWS_64: default key policy (account root only) is intended; see modules/network/aws
  description             = "Secrets Manager encryption for ${local.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${local.name}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# The secret's *value* is never in Terraform. It is written by `platformctl secrets rotate --execute`.
resource "aws_secretsmanager_secret" "app" {
  # checkov:skip=CKV2_AWS_57: rotation is performed by `platformctl secrets rotate` (docs/runbooks/rotate-secrets.md), not a Lambda
  name                    = "${local.name}/app"
  description             = "Runtime secret for the secure-api service"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = 30
  tags                    = var.tags
}

locals {
  read_secret = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadAppSecret"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = aws_secretsmanager_secret.app.arn
      },
      {
        Sid      = "DecryptWithSecretsKey"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.secrets.arn
      },
    ]
  })
}

resource "aws_iam_role_policy" "vm_reads_secret" {
  name   = "read-app-secret"
  role   = var.iam_role_name
  policy = local.read_secret
}
