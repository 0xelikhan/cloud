# cloud-attack-labs

Vulnerable-by-design cloud environments for hands-on attack and defense practice, each the real
upstream project, included here as a git submodule so this repo is a single launch point.

```bash
> **Cost warning.** The AWS/Azure/GCP labs deploy real, billable cloud resources. Only
> `kubernetes-goat` is free (it runs on the home lab's MicroK8s). Read [COST-CONTROLS.md](COST-CONTROLS.md)
> before deploying any cloud lab, and **always tear down** when finished.

## Labs

| Lab | Platform | Cost | Status |
|---|---|---|---|
| [kubernetes-goat](kubernetes-goat-notes.md) | Kubernetes | free (on-prem MicroK8s) | **deployed** on `k8s-01` |
| [cloudgoat](https://github.com/0xelikhan/cloudgoat) | AWS | billable, destroy after use | submodule, needs AWS account |
| [AzureGoat](https://github.com/0xelikhan/AzureGoat) | Azure | billable, needs a subscription | submodule, needs Azure subscription |
| [GCPGoat](https://github.com/0xelikhan/GCPGoat) | GCP | billable, destroy after use | submodule, needs GCP account |
| AWSGoat | AWS | billable | not forked yet — fork `ine-labs/AWSGoat` to add |

## Deploy / teardown (summary)

Each submodule has its own full instructions. The essentials:

### cloudgoat (AWS)
```bash
cd cloudgoat && pip install -r core/python/requirements.txt
./cloudgoat.py create <scenario>     # e.g. iam_privesc_by_rollback
./cloudgoat.py destroy <scenario>    # ALWAYS run when done
```

### AzureGoat (Azure) / GCPGoat (GCP)
Terraform-based. From the submodule:
```bash
terraform init && terraform apply     # deploys billable resources
terraform destroy                     # ALWAYS run when done
```

### kubernetes-goat (free, already running)
Deployed on the home lab's `k8s-01` (MicroK8s). See [kubernetes-goat-notes.md](kubernetes-goat-notes.md).

## Rule of thumb

Deploy a cloud lab, do one scenario, destroy it the same session. Never leave a lab running
overnight. Set a budget alert on each cloud account first.
