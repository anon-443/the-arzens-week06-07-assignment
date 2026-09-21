# Task 5 — Secure Terraform Infrastructure

## Prerequisites

Install Terraform and configure AWS credentials through an approved identity method. Create an existing EC2 key pair and choose an administrator CIDR that is as narrow as possible. Do not place access keys in this repository.

## Deployment

```bash
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with local, non-committed values
terraform init
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

The example creates a VPC, a subnet, a restricted security group, an Ubuntu EC2 instance, and a private encrypted versioned S3 bucket. The instance has no public address, requires IMDSv2, and uses an encrypted root volume. Production deployments should replace the commented backend with an encrypted, versioned, locked remote backend and should run policy checks such as tfsec or OPA before apply.

## Teardown

Only after reviewing impact, run `terraform destroy`. Keep the S3 bucket's `force_destroy = false` behavior so evidence is not silently deleted.
