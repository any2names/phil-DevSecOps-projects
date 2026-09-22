# Runbook: first deployment

Prerequisites (one-time, per cloud):

## Azure
1. `az ad app create --display-name sap-github-oidc`, then add a federated credential for `repo:<owner>/<repo>:environment:prod`.
2. Grant the app **Contributor** on the subscription (or a dedicated resource group) and **Key Vault Data Access Administrator** so it can create the role assignment.
3. Create the state storage account and replace `tfstateplaceholder` / `rg-tfstate-placeholder` in `infra/terragrunt.hcl`.
4. Add environment secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` to the `prod` environment.

## AWS
1. Create the GitHub OIDC provider in IAM (`token.actions.githubusercontent.com`).
2. Create a role trusting `repo:<owner>/<repo>:environment:prod` with permissions for EC2, VPC, IAM (role/profile/policy), KMS, Secrets Manager, CloudWatch Logs, S3/DynamoDB for state.
3. Create the state bucket + lock table and replace `tfstate-placeholder` in `infra/terragrunt.hcl`.
4. Add `AWS_ROLE_ARN` to the `prod` environment.
5. Resolve the Ubuntu 22.04 AMI for the region and replace `ami-0123456789abcdef0` in `infra/envs/<env>/aws/terragrunt.hcl`:
   `aws ssm get-parameter --name /aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id --query Parameter.Value --output text`

## Both
6. Set `PLATFORM_SSH_PUBLIC_KEY` (your admin public key) as an environment variable/secret and replace `203.0.113.0/24` with your admin egress CIDR.
7. Create the GitHub environment `prod` with at least one required reviewer.

## Deploy
1. Actions → **apply** → Run workflow → choose cloud and environment. Approve when prompted.
2. Download the `inventory-<cloud>-<env>` artifact into `ansible/inventory/`.
3. Seed the runtime secret: set `adapter = "<cloud>"` in `platformctl.toml` (Azure: export `AZURE_KEY_VAULT_URL`), then `platformctl secrets rotate app --execute`.
4. `cd ansible && ansible-playbook -i inventory/<cloud>-<env>.yml playbooks/site.yml -e app_deploy_domain=<fqdn> -e app_deploy_acme_email=<email>`
5. `curl https://<fqdn>/api/v1/status` — expect `secret_configured: true`.
6. Record the baseline: `platformctl drift <cloud> <env> --accept`.
