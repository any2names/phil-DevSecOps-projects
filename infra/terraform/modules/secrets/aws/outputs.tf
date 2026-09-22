output "secret_store_id" {
  value = aws_secretsmanager_secret.app.arn
}

output "secret_store_uri" {
  value = aws_secretsmanager_secret.app.name
}
