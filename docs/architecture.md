# Architecture

## Infrastructure topology

```mermaid
flowchart LR
  subgraph Azure["Azure (stack: infra/terraform/stacks/azure)"]
    direction TB
    ARG[Resource group] --> AVN[VNet 10.10.0.0/16]
    AVN --> ASN[Subnet app 10.10.1.0/24]
    ASN --> ANSG[NSG: 443 from Internet<br/>22 from admin CIDRs<br/>deny all]
    ASN --> AVM[Ubuntu 22.04 VM<br/>encryption at host<br/>user-assigned identity]
    AKV[Key Vault via ARM template<br/>RBAC · purge protection · no public network] -. Key Vault Secrets User .-> AVM
  end
  subgraph AWS["AWS (stack: infra/terraform/stacks/aws)"]
    direction TB
    VPC[VPC 10.20.0.0/16] --> SN[Public subnet 10.20.1.0/24]
    SN --> SG[SG: 443 from 0.0.0.0/0<br/>22 per admin CIDR]
    SN --> EC2[Ubuntu 22.04 EC2<br/>IMDSv2 · encrypted gp3 · instance profile]
    VPC --> FL[Flow logs → CloudWatch, KMS]
    SM[Secrets Manager + CMK] -. GetSecretValue .-> EC2
  end
  Admin((Admin CIDR)) -- 22 --> AVM & EC2
  Internet((Internet)) -- 443 --> AVM & EC2
```

Both stacks expose the same outputs (`vm_public_ip`, `vm_private_ip`, `secret_store_id`, `secret_store_uri`, `identity_id`), which is what lets `platformctl ansible inventory` and the Ansible roles be cloud-agnostic ([ADR-0001](adr/0001-multi-cloud-module-contract.md)).

## Pipeline

```mermaid
flowchart LR
  PR[Pull request] --> L[ruff · mypy · pytest ≥85%]
  PR --> T[terraform fmt · validate · terraform test<br/>× azure,aws × dev,prod]
  T --> P[terragrunt plan → JSON<br/>platformctl plan — hermetic, no credentials]
  P --> O{OPA / Conftest<br/>6 policy namespaces}
  PR --> S[platformctl scan<br/>checkov · tfsec · gitleaks · trivy → SARIF]
  S --> ST[(GitHub Security tab)]
  PR --> A[ansible-lint · Molecule converge+verify]
  PR --> R[arm-ttk]
  PR --> C[docker build · smoke · trivy image]
  O -->|deny| X[PR blocked]
  Tag[git tag v*] --> B[build → GHCR]
  B --> G[syft SBOM · cosign keyless sign+attest · verify]
  B --> V[SLSA L3 provenance]
  M[workflow_dispatch] --> E{environment: prod<br/>required reviewer}
  E --> OIDC[OIDC federation<br/>no stored cloud secrets] --> AP[terragrunt apply<br/>TG_BACKEND=remote] --> INV[platformctl ansible inventory]
```

## Identity and secret flow

```mermaid
sequenceDiagram
  participant TF as Terraform
  participant KV as Key Vault / Secrets Manager
  participant OP as Operator (platformctl)
  participant VM as VM (managed identity)
  participant SVC as secure-api.service
  TF->>KV: create store + grant VM identity read-only
  Note over TF,KV: no secret values in Terraform or state
  OP->>KV: platformctl secrets rotate app --execute
  KV-->>OP: new version id (value never printed)
  SVC->>VM: ExecStartPre fetch-secret.sh (root)
  VM->>KV: IMDS token → GET secret (Azure) / aws secretsmanager (AWS)
  KV-->>VM: value
  VM->>SVC: /etc/secure-api/env (0640 root:secure-api)
  SVC->>SVC: start as non-root, ProtectSystem=strict, secret only in memory
```

## Component responsibilities

| Component | Owns | Does not own |
|---|---|---|
| Terraform modules | resources, security defaults, variable validation | environment values, state config |
| Terragrunt | env/cloud layering, backend and provider generation | resource definitions |
| ARM template | Key Vault definition | who can read it (Terraform role assignment) |
| OPA policies | what a plan may contain | how resources are built |
| Ansible | OS hardening, service deployment, secret fetch script | provisioning |
| platformctl | orchestration, parsing, reporting, gating | any cloud resource definition |
| GitHub Actions | ordering, isolation, permissions, artifacts | logic (delegates to platformctl / make) |
