# AWS Data Infrastructure Guide — Download and Use Information

## File Included

**File name:** `aws_data_infrastructure_ami_ansible_guide.html`

**Format:** Single-page HTML file

**Purpose:** Client-ready AWS data infrastructure support guide covering AMI-based EC2 servers, running data service clusters, Ansible configuration, GitLab CI/CD, AWS Systems Manager, Terraform, CloudFormation, backups, failover, clustering, and operational readiness.

## How to Use the HTML Guide

1. Download the HTML file.
2. Save it to a local folder on your computer.
3. Open the file in a modern web browser such as Chrome, Edge, Firefox, or Safari.
4. Use the table of contents to move between sections.
5. Use **Expand All Sections** to show the full guide.
6. Use **Collapse All** to simplify the page.
7. Use the **Dark / Light** button to change display mode.
8. Use the **A−** and **A+** buttons to adjust font size from 14px to 36px.

## Recommended Client Delivery

Send the file as:

```text
aws_data_infrastructure_ami_ansible_guide.html
```

Recommended message:

```text
Attached is the AWS Data Infrastructure Support Guide. It is a single-page HTML document that can be opened directly in a browser. It includes guidance for AMI-based EC2 servers, running Kafka/NiFi/OpenSearch/PostgreSQL/ETL services, clustering, failover, backups, AWS Systems Manager operations, Terraform, CloudFormation, and GitLab CI/CD.
```

## What the Guide Covers

- Amazon Linux 2023 base AMIs
- Golden AMIs
- Custom service-specific AMIs
- Running EC2 servers from approved AMIs
- Kafka clusters ready for producer and consumer use
- ZooKeeper support for legacy systems
- NiFi clusters ready for flows
- PostgreSQL/RDS/Aurora options
- OpenSearch cluster readiness
- ETL worker servers
- Ansible roles and configuration
- GitLab CI/CD pipeline controls
- AWS Systems Manager operations
- Terraform and CloudFormation deployment
- Manual and automated backup processes
- Multi-AZ clustering
- Load management
- Failover and fault tolerance
- Pros and cons decision matrix

## Notes for Production Use

Before using this guide as a production standard, review it with:

- Cloud governance team
- Security team
- Data platform owners
- Network team
- Compliance team
- Backup and disaster recovery team
- Application owners

## Recommended Next Step

Use this guide as the foundation for:

- AWS infrastructure support standards
- Data platform onboarding documentation
- AMI lifecycle procedures
- GitLab CI/CD deployment patterns
- SSM runbooks
- Disaster recovery planning
- Client-facing AWS platform recommendations
