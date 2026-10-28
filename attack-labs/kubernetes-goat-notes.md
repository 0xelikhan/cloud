# kubernetes-goat (deployed)

Deployed on the home lab's `k8s-01` MicroK8s cluster. Free, isolated, nothing billable.

## What's running

The full kubernetes-goat scenario set, deployed with the upstream installer:

```bash
# on k8s-01 (MicroK8s), ubuntu user in the microk8s group
cd ~/kubernetes-goat
bash setup-kubernetes-goat.sh
```

Scenarios include: sensitive-keys-in-codebase, DIND, SSRF, container escape, docker-in-docker,
SICC, hidden-in-layers, RBAC least privilege, KubeAudit, hunger-check (Hunger API), build-code,
poor-registry, system-monitor, and more. Each is a namespace/deployment in the cluster.

## Access

```bash
# on k8s-01
cd ~/kubernetes-goat
bash access-kubernetes-goat.sh      # sets up kubectl port-forwards
# then browse the goat home at the forwarded port; reach k8s-01 over the tailnet
```

## Teardown

```bash
cd ~/kubernetes-goat
bash teardown-kubernetes-goat.sh
```

## Notes

- Uses the home lab MicroK8s, so there is no cloud cost. Prefer this for Kubernetes-security work.
- Intentionally vulnerable: keep it on the isolated lab network, never expose it.
