# cloud

Cloud-native detection engineering — AWS infrastructure provisioned with Terraform, Microsoft Sentinel with KQL detection rules, Splunk SPL queries, and LimaCharlie cloud EDR.

## Repos in this portfolio

| Repo | What it covers |
|------|---------------|
| [detection-rules](https://github.com/YOUR-USERNAME/detection-rules) | Sigma + YARA rules, CI/CD validation pipeline |
| [homelab](https://github.com/YOUR-USERNAME/homelab) | On-prem SOC lab — Wazuh, Velociraptor, pfSense, AD |
| **cloud** | AWS, Sentinel/KQL, Splunk/SPL, LimaCharlie |
| [scripts](https://github.com/YOUR-USERNAME/scripts) | Custom Python detection tools |

## Structure

```
cloud/
├── terraform/          AWS lab — VPC, EC2, GuardDuty, CloudTrail
├── sentinel-kql/       KQL detection queries for Microsoft Sentinel
├── splunk-spl/         SPL detection queries mirroring Sigma rule coverage
└── limacharlie/        Cloud EDR configuration and detection output
```

## Why cloud is a separate repo

Cloud detection is screened for separately on detection engineer job descriptions. AWS GuardDuty, Sentinel, and Splunk each appear as standalone requirements. Keeping this work isolated makes it immediately visible as a distinct skill set rather than buried inside a lab monorepo.
