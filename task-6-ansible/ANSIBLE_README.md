# Task 6 — Ansible Hardening and Compliance

Update `hosts.ini` with private addresses and verify SSH access before running. The playbooks target Debian/Ubuntu systems and are intentionally idempotent.

```bash
ansible all -m ping
ansible-playbook -i hosts.ini site.yml --check --diff
ansible-playbook -i hosts.ini site.yml
ansible-playbook -i hosts.ini security.yml
cat compliance_report.txt
```

The hardening role enables unattended upgrades, disables SSH root login and password authentication, configures UFW with default deny, enables fail2ban and auditd, and writes audit rules. Test firewall and SSH changes through a maintenance path so that an administrator is not locked out.
