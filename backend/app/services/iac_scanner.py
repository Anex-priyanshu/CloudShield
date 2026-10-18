"""IaC Scanner service – parses Terraform and CloudFormation files, runs checks, and computes risk scores."""
import os
import re
import json
import logging
import tempfile
import shutil
from typing import List, Dict, Any, Tuple
from app.services.risk_engine import compute_risk_score

logger = logging.getLogger(__name__)

SAMPLE_INSECURE_TF = """# Insecure Infrastructure as Code Sample (CloudShield Demo)
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-pii-records-prod"
  acl    = "public-read" # Critical: Public read access
  tags = {
    Environment = "prod"
    data-classification = "confidential"
  }
}

resource "aws_security_group" "allow_ssh_world" {
  name        = "launch-wizard-1"
  description = "Management SG"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Critical: SSH open to 0.0.0.0/0
  }

  ingress {
    description = "PostgreSQL DB port open"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # High: Database port open to internet
  }
}

resource "aws_ebs_volume" "app_data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false # High: Unencrypted EBS volume
}

resource "aws_db_instance" "production_db" {
  allocated_storage   = 50
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true # Critical: DB instance publicly accessible
  storage_encrypted   = false
}
"""

SAMPLE_SECURE_TF = """# Secure Infrastructure as Code Sample (CloudShield Demo)
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-pii-records-prod"
  tags = {
    Environment = "prod"
    data-classification = "confidential"
  }
}

resource "aws_s3_bucket_public_access_block" "customer_data_block" {
  bucket                  = aws_s3_bucket.customer_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "web_sg" {
  name        = "web-tier-sg"
  description = "Production Web Tier"

  ingress {
    description = "HTTPS only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"] # Restricted to VPC
  }
}

resource "aws_ebs_volume" "app_data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true # Compliant
}

resource "aws_db_instance" "production_db" {
  allocated_storage   = 50
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = false # Secure
  storage_encrypted   = true  # Encrypted
}
"""


def scan_terraform_content(filename: str, content: str) -> List[Dict[str, Any]]:
    """Static analysis of Terraform content against key security checks."""
    findings = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, 1):
        # S3 Public Read
        if re.search(r'acl\s*=\s*["\']public-read["\']', line, re.I):
            score, band = compute_risk_score(5, 5, 4)
            findings.append({
                "check_id": "CKV_AWS_20",
                "check_name": "S3 Bucket has an ACL allowing public read access",
                "file_path": filename,
                "line_start": idx,
                "line_end": idx,
                "resource": "aws_s3_bucket",
                "severity": 5,
                "exposure": 5,
                "data_sensitivity": 4,
                "risk_score": score,
                "band": band,
                "guideline": "Ensure S3 bucket does not have public-read ACL. Use S3 Block Public Access.",
            })

        # S3 Public Read-Write
        if re.search(r'acl\s*=\s*["\']public-read-write["\']', line, re.I):
            score, band = compute_risk_score(5, 5, 5)
            findings.append({
                "check_id": "CKV_AWS_57",
                "check_name": "S3 Bucket has an ACL allowing public read and write access",
                "file_path": filename,
                "line_start": idx,
                "line_end": idx,
                "resource": "aws_s3_bucket",
                "severity": 5,
                "exposure": 5,
                "data_sensitivity": 5,
                "risk_score": score,
                "band": band,
                "guideline": "Never permit public-read-write ACLs on AWS S3 buckets.",
            })

        # Security Group 0.0.0.0/0 on SSH / RDP / DB
        if '0.0.0.0/0' in line:
            # check previous 5 lines for context
            context = "\n".join(lines[max(0, idx - 6):idx])
            if re.search(r'22|ssh', context, re.I):
                score, band = compute_risk_score(5, 5, 3)
                findings.append({
                    "check_id": "CKV_AWS_24",
                    "check_name": "Security Group allows open SSH port (22) from internet (0.0.0.0/0)",
                    "file_path": filename,
                    "line_start": max(1, idx - 4),
                    "line_end": idx,
                    "resource": "aws_security_group",
                    "severity": 5,
                    "exposure": 5,
                    "data_sensitivity": 3,
                    "risk_score": score,
                    "band": band,
                    "guideline": "Restrict SSH access (port 22) to specific trusted bastion or VPN CIDR blocks.",
                })
            elif re.search(r'3389|rdp', context, re.I):
                score, band = compute_risk_score(5, 5, 3)
                findings.append({
                    "check_id": "CKV_AWS_25",
                    "check_name": "Security Group allows open RDP port (3389) from internet (0.0.0.0/0)",
                    "file_path": filename,
                    "line_start": max(1, idx - 4),
                    "line_end": idx,
                    "resource": "aws_security_group",
                    "severity": 5,
                    "exposure": 5,
                    "data_sensitivity": 3,
                    "risk_score": score,
                    "band": band,
                    "guideline": "Restrict RDP access (port 3389) to private IP addresses.",
                })
            elif re.search(r'5432|3306|1433|27017|database|db', context, re.I):
                score, band = compute_risk_score(5, 5, 4)
                findings.append({
                    "check_id": "CKV_AWS_260",
                    "check_name": "Security Group exposes database port directly to 0.0.0.0/0",
                    "file_path": filename,
                    "line_start": max(1, idx - 4),
                    "line_end": idx,
                    "resource": "aws_security_group",
                    "severity": 5,
                    "exposure": 5,
                    "data_sensitivity": 4,
                    "risk_score": score,
                    "band": band,
                    "guideline": "Database ports must never be exposed to the public internet.",
                })

        # EBS Unencrypted
        if re.search(r'encrypted\s*=\s*false', line, re.I):
            score, band = compute_risk_score(3, 2, 3)
            findings.append({
                "check_id": "CKV_AWS_3",
                "check_name": "EBS Volume encryption is explicitly disabled",
                "file_path": filename,
                "line_start": idx,
                "line_end": idx,
                "resource": "aws_ebs_volume",
                "severity": 3,
                "exposure": 2,
                "data_sensitivity": 3,
                "risk_score": score,
                "band": band,
                "guideline": "Set encrypted = true and optionally configure KMS Key ARN for EBS volume.",
            })

        # RDS Publicly Accessible
        if re.search(r'publicly_accessible\s*=\s*true', line, re.I):
            score, band = compute_risk_score(5, 5, 4)
            findings.append({
                "check_id": "CKV_AWS_17",
                "check_name": "RDS DB Instance is set to publicly accessible",
                "file_path": filename,
                "line_start": idx,
                "line_end": idx,
                "resource": "aws_db_instance",
                "severity": 5,
                "exposure": 5,
                "data_sensitivity": 4,
                "risk_score": score,
                "band": band,
                "guideline": "Ensure RDS instances are placed in private subnets and publicly_accessible is false.",
            })

        # RDS Unencrypted
        if re.search(r'storage_encrypted\s*=\s*false', line, re.I):
            score, band = compute_risk_score(4, 3, 3)
            findings.append({
                "check_id": "CKV_AWS_16",
                "check_name": "RDS DB storage encryption is disabled",
                "file_path": filename,
                "line_start": idx,
                "line_end": idx,
                "resource": "aws_db_instance",
                "severity": 4,
                "exposure": 3,
                "data_sensitivity": 3,
                "risk_score": score,
                "band": band,
                "guideline": "Enable storage encryption (storage_encrypted = true) for RDS instances.",
            })

    return findings


def run_iac_analysis(files: List[Tuple[str, str]]) -> Dict[str, Any]:
    """
    Takes a list of (filename, file_content) tuples, evaluates IaC rules,
    and returns findings, summary statistics, and deployment gate verdict (PASS/FAIL).
    """
    all_findings = []
    for filename, content in files:
        results = scan_terraform_content(filename, content)
        all_findings.extend(results)

    critical_count = sum(1 for f in all_findings if f["severity"] == 5 or f["band"] == "critical")
    high_count = sum(1 for f in all_findings if f["severity"] == 4 or f["band"] == "high")
    medium_count = sum(1 for f in all_findings if f["severity"] == 3 or f["band"] == "medium")
    low_count = sum(1 for f in all_findings if f["severity"] <= 2 or f["band"] == "low")

    # Gate verdict: FAIL if any High or Critical finding
    verdict = "FAIL" if (critical_count > 0 or high_count > 0) else "PASS"

    summary = {
        "verdict": verdict,
        "total_findings": len(all_findings),
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "gate_reason": "Failed deployment gate: Critical or High severity misconfigurations detected." if verdict == "FAIL" else "Passed deployment gate: No blocking High/Critical misconfigurations."
    }

    return {
        "verdict": verdict,
        "summary": summary,
        "findings": all_findings,
    }
