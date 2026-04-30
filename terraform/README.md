# Terraform — AWS Cloud Lab

AWS infrastructure provisioned with Terraform. Mirrors the on-prem lab's detection scenarios in a cloud-native environment — EC2 victim with GuardDuty, CloudTrail, and VPC flow logs feeding detection.

## Infrastructure provisioned
| Resource | Purpose |
|----------|---------|
| VPC + subnets | Isolated cloud lab network |
| EC2 Ubuntu t2.micro | Victim instance (free tier) |
| GuardDuty | AWS-native threat detection |
| CloudTrail | API activity logging to S3 |
| VPC flow logs | Network-level visibility |
| S3 bucket | Log storage |

## Usage
```bash
cd terraform/
terraform init
terraform plan
terraform apply
```

**Note:** AWS credentials are never stored here. Use `aws configure` or set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` as environment variables. `.gitignore` excludes all `.tfstate` files.

## Screenshots
<!-- Add after build -->
![terraform apply completing](screenshots/terraform-apply.png)
![AWS GuardDuty findings](screenshots/guardduty-findings.png)
![EC2 instance in console](screenshots/aws-ec2.png)
