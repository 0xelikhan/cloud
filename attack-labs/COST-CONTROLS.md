# Cost controls

The AWS/Azure/GCP labs create real resources that cost money. Do this before deploying any of them.

## Before you deploy

- **Set a budget alert** on each account:
  - AWS: Billing → Budgets → a low monthly budget with an email alert.
  - Azure: Cost Management → Budgets.
  - GCP: Billing → Budgets & alerts.
- **Use a separate account / project** from anything real, never a production account.
- **Use least-privilege deploy credentials**, and rotate or disable them after.

## While using a lab

- Deploy, do one scenario, **destroy the same session**. Do not leave resources overnight.
- CloudGoat and the Goat Terraform stacks spin up compute, storage and sometimes managed services
  that bill hourly. A forgotten NAT gateway, running EC2/VM, or GuardDuty detector is the usual
  surprise on the bill.

## Teardown checklist

- `cloudgoat destroy <scenario>` / `terraform destroy` returns success with **no resources left**.
- In the console, confirm: no running compute, no NAT gateways, no load balancers, storage emptied.
- Disable any detectors/services the lab enabled (GuardDuty, Defender for Cloud) if you turned them on.

## Not billable

`kubernetes-goat` runs on the home lab's MicroK8s (`k8s-01`), so it costs nothing. Prefer it for
Kubernetes-security practice.
