package terraform.secrets_test

import rego.v1

import data.terraform.secrets

res(type, after) := {"resource_changes": [{"address": concat(".", [type, "x"]), "type": type, "change": {"actions": ["create"], "after": after}}]}

test_secret_version_resource_denied if {
	count(secrets.deny) == 1 with input as res("aws_secretsmanager_secret_version", {"secret_string": "anything"})
}

test_access_key_pattern_denied if {
	count(secrets.deny) == 1 with input as res("aws_instance", {"user_data": "export AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"})
}

test_nested_private_key_denied if {
	count(secrets.deny) == 1 with input as res("aws_instance", {"metadata": {"k": "-----BEGIN RSA PRIVATE KEY-----"}})
}

test_clean_resource_ok if {
	count(secrets.deny) == 0 with input as res("aws_instance", {"ami": "ami-0123456789abcdef0", "tags": {"a": "b"}})
}
