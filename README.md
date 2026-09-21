# THE ARZENS Advanced Track — Week 06–07 Combined Assignment

This repository contains the six requested deliverables for **Threat Intelligence Automation** and **Infrastructure as Code Security Engineering**. The implementation is designed to be safe to run without credentials: API integrations degrade gracefully, secrets are read from environment variables or ignored local files, and all examples use documentation-only values.

## Repository map

| Task | Location | Main deliverables |
|---|---|---|
| 1 | `docs/ti-architecture.md` | TI architecture design and diagram |
| 2 | `task-2-ti-enrichment/` | Multi-source Python enrichment engine |
| 3 | `task-3-ioc-manager/` | IOC lifecycle manager, blocklist, report |
| 4 | `docs/iac-security-architecture.md` | IaC security design and module diagram |
| 5 | `task-5-terraform/` | Secure AWS Terraform configuration |
| 6 | `task-6-ansible/` | Idempotent hardening roles and compliance checks |

The PDFs required for Tasks 1 and 4 are in `docs/` and are generated from the reviewed Markdown source files.

## Safety and credential handling

Never commit real API keys, cloud credentials, private keys, or `terraform.tfvars`. Copy the provided examples into local files and populate them from a secret manager or environment variables. The `.gitignore` file protects common local secret and state files.

## Quick validation

```bash
python3 -m py_compile task-2-ti-enrichment/ti_enricher.py task-3-ioc-manager/ioc_manager.py
python3 task-2-ti-enrichment/ti_enricher.py --input-file task-2-ti-enrichment/sample_indicators.csv --format csv --output /tmp/enrichment.csv --offline
python3 task-3-ioc-manager/ioc_manager.py --add-file task-3-ioc-manager/sample_indicators.csv --db /tmp/ioc_database.json --offline
python3 task-3-ioc-manager/ioc_manager.py --export-blocklist --db /tmp/ioc_database.json --output /tmp/blocklist.txt
terraform -chdir=task-5-terraform fmt -check  # if Terraform is installed
ansible-playbook -i task-6-ansible/hosts.ini task-6-ansible/site.yml --syntax-check  # if Ansible is installed
```

## AI assistance note

AI assistance was used to accelerate drafting and code review. All files were manually structured around the assignment rubric, use explicit security controls, and were validated for syntax and offline behavior. No live secrets are included.
