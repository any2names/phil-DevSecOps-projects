output "vm_public_ip" {
  value = aws_eip.vm.public_ip
}

output "vm_private_ip" {
  value = aws_instance.this.private_ip
}

output "identity_id" {
  value = aws_iam_role.vm.arn
}

output "iam_role_name" {
  value = aws_iam_role.vm.name
}
