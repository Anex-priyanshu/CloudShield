"""S3 security checks: S3-001 through S3-006."""
from typing import Any, Dict, List
from app.checks.base import BaseCheck, CheckResult


def _is_public(bucket: Dict) -> bool:
    acl = bucket.get("ACL", "private")
    if acl in ("public-read", "public-read-write", "authenticated-read"):
        return True
    pab = bucket.get("PublicAccessBlock", {})
    if pab:
        all_blocked = all([
            pab.get("BlockPublicAcls", False),
            pab.get("BlockPublicPolicy", False),
            pab.get("IgnorePublicAcls", False),
            pab.get("RestrictPublicBuckets", False),
        ])
        return not all_blocked
    return False


class S3001PublicBucket(BaseCheck):
    check_id = "S3-001"
    title = "S3 bucket allows public access"
    category = "Storage"
    severity = 5
    cis_control = "CIS 2.1.5"
    description = "S3 buckets should not be publicly accessible."
    why_it_matters = "Public buckets expose data to the entire internet – a leading cause of cloud data breaches."
    remediation = "1. Enable Block Public Access for the bucket.\n2. Review and restrict bucket ACL and policy."
    cli_fix = "aws s3api put-public-access-block --bucket <BUCKET> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for bucket in resource.get("s3_buckets", []):
            if _is_public(bucket):
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False,
                    resource_id=f"arn:aws:s3:::{bucket['Name']}",
                    resource_type="AWS::S3::Bucket", region=bucket.get("Region", "us-east-1"),
                    evidence={"BucketName": bucket["Name"], "ACL": bucket.get("ACL"), "PublicAccessBlock": bucket.get("PublicAccessBlock")},
                    exposure=5, data_sensitivity_hint=3,
                    tags=bucket.get("Tags", {}),
                ))
        return results


class S3002AccountPublicAccess(BaseCheck):
    check_id = "S3-002"
    title = "Account-level S3 Block Public Access disabled"
    category = "Storage"
    severity = 4
    cis_control = "CIS 2.1.5"
    description = "Account-level S3 Block Public Access should be enabled."
    why_it_matters = "Account-level BPA is the last safety net against accidentally public buckets."
    remediation = "Enable S3 Block Public Access at the account level in AWS console or CLI."
    cli_fix = "aws s3control put-public-access-block --account-id <ACCOUNT_ID> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        if not resource.get("account_level_public_access_block", True):
            results.append(CheckResult(
                check_id=self.check_id, title=self.title, category=self.category,
                severity=self.severity, cis_control=self.cis_control,
                description=self.description, why_it_matters=self.why_it_matters,
                remediation=self.remediation, cli_fix=self.cli_fix,
                passed=False, resource_id=f"arn:aws:s3:::ACCOUNT/{resource.get('account_id','unknown')}",
                resource_type="AWS::S3::AccountPublicAccessBlock",
                region="global", evidence={"account_level_public_access_block": False},
                exposure=4, data_sensitivity_hint=3,
            ))
        return results


class S3003Encryption(BaseCheck):
    check_id = "S3-003"
    title = "S3 bucket default encryption disabled"
    category = "Storage"
    severity = 3
    cis_control = "CIS 2.1.1"
    description = "S3 buckets should have default encryption enabled."
    why_it_matters = "Without encryption, data at rest is vulnerable if storage media is accessed."
    remediation = "Enable server-side encryption (SSE-S3 or SSE-KMS) on the bucket."
    cli_fix = 'aws s3api put-bucket-encryption --bucket <BUCKET> --server-side-encryption-configuration \'{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}\''

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for bucket in resource.get("s3_buckets", []):
            if not bucket.get("Encryption"):
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False, resource_id=f"arn:aws:s3:::{bucket['Name']}",
                    resource_type="AWS::S3::Bucket", region=bucket.get("Region", "us-east-1"),
                    evidence={"BucketName": bucket["Name"], "Encryption": None},
                    exposure=2, data_sensitivity_hint=3,
                    tags=bucket.get("Tags", {}),
                ))
        return results


class S3004Versioning(BaseCheck):
    check_id = "S3-004"
    title = "S3 bucket versioning disabled"
    category = "Storage"
    severity = 2
    cis_control = "CIS 2.1.3"
    description = "S3 buckets should have versioning enabled."
    why_it_matters = "Versioning protects against accidental deletion and ransomware attacks."
    remediation = "Enable S3 versioning for the bucket."
    cli_fix = "aws s3api put-bucket-versioning --bucket <BUCKET> --versioning-configuration Status=Enabled"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for bucket in resource.get("s3_buckets", []):
            if not bucket.get("Versioning"):
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False, resource_id=f"arn:aws:s3:::{bucket['Name']}",
                    resource_type="AWS::S3::Bucket", region=bucket.get("Region", "us-east-1"),
                    evidence={"BucketName": bucket["Name"], "Versioning": False},
                    exposure=1, data_sensitivity_hint=2,
                    tags=bucket.get("Tags", {}),
                ))
        return results


class S3005AccessLogging(BaseCheck):
    check_id = "S3-005"
    title = "S3 bucket access logging disabled"
    category = "Storage"
    severity = 2
    cis_control = "CIS 2.1.4"
    description = "S3 buckets should have access logging enabled."
    why_it_matters = "Without logging, unauthorized access cannot be detected or investigated."
    remediation = "Enable S3 server access logging, pointing to a log bucket."
    cli_fix = 'aws s3api put-bucket-logging --bucket <BUCKET> --bucket-logging-status \'{"LoggingEnabled": {"TargetBucket": "<LOG_BUCKET>", "TargetPrefix": ""}}\''

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for bucket in resource.get("s3_buckets", []):
            if not bucket.get("LoggingEnabled"):
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False, resource_id=f"arn:aws:s3:::{bucket['Name']}",
                    resource_type="AWS::S3::Bucket", region=bucket.get("Region", "us-east-1"),
                    evidence={"BucketName": bucket["Name"], "LoggingEnabled": False},
                    exposure=1, data_sensitivity_hint=2,
                    tags=bucket.get("Tags", {}),
                ))
        return results


class S3006HTTPS(BaseCheck):
    check_id = "S3-006"
    title = "S3 bucket does not enforce HTTPS"
    category = "Storage"
    severity = 3
    cis_control = "CIS 2.1.2"
    description = "Bucket policy should deny HTTP requests (aws:SecureTransport)."
    why_it_matters = "Without HTTPS enforcement, data in transit can be intercepted."
    remediation = "Add a bucket policy that denies s3:GetObject when aws:SecureTransport is false."
    cli_fix = '# Add a bucket policy with Condition: {"Bool": {"aws:SecureTransport": "false"}} → Deny'

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for bucket in resource.get("s3_buckets", []):
            if not bucket.get("HttpsEnforced"):
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False, resource_id=f"arn:aws:s3:::{bucket['Name']}",
                    resource_type="AWS::S3::Bucket", region=bucket.get("Region", "us-east-1"),
                    evidence={"BucketName": bucket["Name"], "HttpsEnforced": False},
                    exposure=3, data_sensitivity_hint=3,
                    tags=bucket.get("Tags", {}),
                ))
        return results


ALL_S3_CHECKS = [
    S3001PublicBucket(),
    S3002AccountPublicAccess(),
    S3003Encryption(),
    S3004Versioning(),
    S3005AccessLogging(),
    S3006HTTPS(),
]
