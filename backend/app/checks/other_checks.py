"""Network, Logging, Encryption, and Backup checks."""
from typing import Any, Dict, List
from app.checks.base import BaseCheck, CheckResult

DB_PORTS = {3306, 5432, 1433, 27017}


def _has_open_ingress(sg: Dict, port: int) -> bool:
    for perm in sg.get("IpPermissions", []):
        from_port = perm.get("FromPort", -1)
        to_port = perm.get("ToPort", -1)
        proto = perm.get("IpProtocol", "")
        # -1 means all
        if proto == "-1":
            for r in perm.get("IpRanges", []) + perm.get("Ipv6Ranges", []):
                cidr = r.get("CidrIp", r.get("CidrIpv6", ""))
                if cidr in ("0.0.0.0/0", "::/0"):
                    return True
        if from_port != -1 and not (from_port <= port <= to_port):
            continue
        for r in perm.get("IpRanges", []) + perm.get("Ipv6Ranges", []):
            cidr = r.get("CidrIp", r.get("CidrIpv6", ""))
            if cidr in ("0.0.0.0/0", "::/0"):
                return True
    return False


def _has_open_all(sg: Dict) -> bool:
    for perm in sg.get("IpPermissions", []):
        proto = perm.get("IpProtocol", "")
        if proto == "-1":
            for r in perm.get("IpRanges", []) + perm.get("Ipv6Ranges", []):
                cidr = r.get("CidrIp", r.get("CidrIpv6", ""))
                if cidr in ("0.0.0.0/0", "::/0"):
                    return True
    return False


# ─── Network ─────────────────────────────────────────────────────────────────
class NET001SSH(BaseCheck):
    check_id = "NET-001"
    title = "Security group allows 0.0.0.0/0 on SSH (port 22)"
    category = "Network"
    severity = 5
    cis_control = "CIS 5.2"
    description = "Security groups should not allow unrestricted SSH access."
    why_it_matters = "Open SSH exposes all instances in the SG to brute-force and exploitation."
    remediation = "Restrict port 22 to specific trusted IP ranges or use AWS Systems Manager Session Manager."
    cli_fix = "aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port 22 --cidr 0.0.0.0/0"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for sg in resource.get("security_groups", []):
            if _has_open_ingress(sg, 22):
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False,
                    resource_id=f"arn:aws:ec2:us-east-1:sg/{sg['GroupId']}",
                    resource_type="AWS::EC2::SecurityGroup", region="us-east-1",
                    evidence={"GroupId": sg["GroupId"], "GroupName": sg.get("GroupName"), "Port": 22},
                    exposure=5, data_sensitivity_hint=3,
                ))
        return results


class NET002RDP(BaseCheck):
    check_id = "NET-002"
    title = "Security group allows 0.0.0.0/0 on RDP (port 3389)"
    category = "Network"
    severity = 5
    cis_control = "CIS 5.3"
    description = "Security groups should not allow unrestricted RDP access."
    why_it_matters = "Open RDP is a primary ransomware attack vector."
    remediation = "Restrict port 3389 to specific trusted IP ranges or use VPN."
    cli_fix = "aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port 3389 --cidr 0.0.0.0/0"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for sg in resource.get("security_groups", []):
            if _has_open_ingress(sg, 3389):
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False,
                    resource_id=f"arn:aws:ec2:us-east-1:sg/{sg['GroupId']}",
                    resource_type="AWS::EC2::SecurityGroup", region="us-east-1",
                    evidence={"GroupId": sg["GroupId"], "GroupName": sg.get("GroupName"), "Port": 3389},
                    exposure=5, data_sensitivity_hint=3,
                ))
        return results


class NET003DBPorts(BaseCheck):
    check_id = "NET-003"
    title = "Security group allows 0.0.0.0/0 on database ports"
    category = "Network"
    severity = 5
    cis_control = "CIS 5.4"
    description = "Database ports should not be open to the internet."
    why_it_matters = "Exposed databases are directly queryable from the internet – prime targets for data theft."
    remediation = "Remove database port rules from internet-facing security groups. Use private subnets."
    cli_fix = "aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port <PORT> --cidr 0.0.0.0/0"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for sg in resource.get("security_groups", []):
            for port in DB_PORTS:
                if _has_open_ingress(sg, port):
                    results.append(CheckResult(
                        check_id=self.check_id, title=self.title, category=self.category,
                        severity=self.severity, cis_control=self.cis_control,
                        description=self.description, why_it_matters=self.why_it_matters,
                        remediation=self.remediation, cli_fix=self.cli_fix,
                        passed=False,
                        resource_id=f"arn:aws:ec2:us-east-1:sg/{sg['GroupId']}",
                        resource_type="AWS::EC2::SecurityGroup", region="us-east-1",
                        evidence={"GroupId": sg["GroupId"], "GroupName": sg.get("GroupName"), "Port": port},
                        exposure=5, data_sensitivity_hint=4,
                    ))
                    break  # one finding per SG for DB ports
        return results


class NET004DefaultSG(BaseCheck):
    check_id = "NET-004"
    title = "Default security group allows traffic"
    category = "Network"
    severity = 3
    cis_control = "CIS 5.4"
    description = "The default security group should restrict all traffic."
    why_it_matters = "New resources are often placed in the default SG by mistake. An open default SG creates unexpected exposure."
    remediation = "Remove all ingress/egress rules from the default security group."
    cli_fix = "aws ec2 revoke-security-group-ingress --group-id <DEFAULT_SG_ID> --protocol -1 --cidr 0.0.0.0/0"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for sg in resource.get("security_groups", []):
            if sg.get("GroupName") == "default" and sg.get("IpPermissions"):
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False,
                    resource_id=f"arn:aws:ec2:us-east-1:sg/{sg['GroupId']}",
                    resource_type="AWS::EC2::SecurityGroup", region="us-east-1",
                    evidence={"GroupId": sg["GroupId"], "GroupName": "default", "HasRules": True},
                    exposure=3, data_sensitivity_hint=3,
                ))
        return results


# ─── Logging ─────────────────────────────────────────────────────────────────
class LOG001CloudTrail(BaseCheck):
    check_id = "LOG-001"
    title = "CloudTrail not enabled in all regions"
    category = "Logging"
    severity = 5
    cis_control = "CIS 3.1"
    description = "CloudTrail should be enabled and multi-region."
    why_it_matters = "Without multi-region CloudTrail, API activity in other regions goes unlogged."
    remediation = "Create a multi-region CloudTrail trail in the AWS console."
    cli_fix = "aws cloudtrail create-trail --name my-trail --s3-bucket-name <BUCKET> --is-multi-region-trail\naws cloudtrail start-logging --name my-trail"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        trails = resource.get("cloudtrail_trails", [])
        has_multiregion_logging = any(
            t.get("IsMultiRegionTrail") and t.get("IsLogging") for t in trails
        )
        if not has_multiregion_logging:
            results.append(CheckResult(
                check_id=self.check_id, title=self.title, category=self.category,
                severity=self.severity, cis_control=self.cis_control,
                description=self.description, why_it_matters=self.why_it_matters,
                remediation=self.remediation, cli_fix=self.cli_fix,
                passed=False, resource_id="arn:aws:cloudtrail:ACCOUNT",
                resource_type="AWS::CloudTrail::Trail", region="global",
                evidence={"trails": trails, "has_multiregion_logging": False},
                exposure=3, data_sensitivity_hint=3,
            ))
        return results


class LOG002Validation(BaseCheck):
    check_id = "LOG-002"
    title = "CloudTrail log file validation disabled"
    category = "Logging"
    severity = 3
    cis_control = "CIS 3.2"
    description = "CloudTrail log file validation should be enabled."
    why_it_matters = "Without validation, log files can be tampered with undetected."
    remediation = "Enable log file validation on the CloudTrail trail."
    cli_fix = "aws cloudtrail update-trail --name <TRAIL_NAME> --enable-log-file-validation"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for trail in resource.get("cloudtrail_trails", []):
            if not trail.get("LogFileValidationEnabled"):
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False,
                    resource_id=trail.get("TrailARN", "unknown"),
                    resource_type="AWS::CloudTrail::Trail", region="us-east-1",
                    evidence={"TrailARN": trail.get("TrailARN"), "LogFileValidationEnabled": False},
                    exposure=2, data_sensitivity_hint=2,
                ))
        return results


# ─── Encryption ──────────────────────────────────────────────────────────────
class ENC001EBSEncryption(BaseCheck):
    check_id = "ENC-001"
    title = "EBS volumes not encrypted"
    category = "Encryption"
    severity = 3
    cis_control = "CIS 2.2.1"
    description = "All EBS volumes should be encrypted."
    why_it_matters = "Unencrypted volumes expose data if the underlying storage is accessed."
    remediation = "1. Create an encrypted snapshot of the volume.\n2. Restore a new encrypted volume from the snapshot."
    cli_fix = "aws ec2 create-snapshot --volume-id <VOLUME_ID>\naws ec2 copy-snapshot --source-snapshot-id <SNAP_ID> --encrypted"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for vol in resource.get("ebs_volumes", []):
            if not vol.get("Encrypted"):
                tags = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False,
                    resource_id=f"arn:aws:ec2:us-east-1:volume/{vol['VolumeId']}",
                    resource_type="AWS::EC2::Volume", region="us-east-1",
                    evidence={"VolumeId": vol["VolumeId"], "Encrypted": False, "Size": vol.get("Size")},
                    exposure=2, data_sensitivity_hint=3,
                    tags=tags,
                ))
        return results


class ENC002RDS(BaseCheck):
    check_id = "ENC-002"
    title = "RDS instances not encrypted or publicly accessible"
    category = "Encryption"
    severity = 4
    cis_control = "CIS 2.3.1"
    description = "RDS instances should be encrypted and not publicly accessible."
    why_it_matters = "Publicly accessible or unencrypted RDS instances expose sensitive data."
    remediation = "1. For encryption: create an encrypted snapshot and restore.\n2. Disable public accessibility in the RDS settings."
    cli_fix = "aws rds modify-db-instance --db-instance-identifier <ID> --no-publicly-accessible"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for rds in resource.get("rds_instances", []):
            issues = []
            exposure = 2
            if not rds.get("StorageEncrypted"):
                issues.append("Not encrypted")
            if rds.get("PubliclyAccessible"):
                issues.append("Publicly accessible")
                exposure = 4
            if issues:
                tags = {t["Key"]: t["Value"] for t in rds.get("Tags", [])}
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False,
                    resource_id=f"arn:aws:rds:us-east-1:db:{rds['DBInstanceIdentifier']}",
                    resource_type="AWS::RDS::DBInstance", region="us-east-1",
                    evidence={"DBInstance": rds["DBInstanceIdentifier"], "Issues": issues},
                    exposure=exposure, data_sensitivity_hint=4,
                    tags=tags,
                ))
        return results


class ENC003KMSRotation(BaseCheck):
    check_id = "ENC-003"
    title = "KMS customer-managed keys without rotation"
    category = "Encryption"
    severity = 2
    cis_control = "CIS 3.8"
    description = "KMS CMKs should have automatic key rotation enabled."
    why_it_matters = "Regular key rotation limits the impact of key compromise."
    remediation = "Enable automatic key rotation for the KMS key."
    cli_fix = "aws kms enable-key-rotation --key-id <KEY_ID>"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for key in resource.get("kms_keys", []):
            if key.get("KeyManager") == "CUSTOMER" and not key.get("RotationEnabled"):
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False,
                    resource_id=key.get("KeyArn", key.get("KeyId")),
                    resource_type="AWS::KMS::Key", region="us-east-1",
                    evidence={"KeyId": key["KeyId"], "RotationEnabled": False},
                    exposure=1, data_sensitivity_hint=2,
                ))
        return results


# ─── Backup ──────────────────────────────────────────────────────────────────
class BKP001RDSBackup(BaseCheck):
    check_id = "BKP-001"
    title = "RDS automated backups disabled or retention < 7 days"
    category = "Backup"
    severity = 3
    cis_control = "CIS 2.3.2"
    description = "RDS instances should have automated backups with ≥7 day retention."
    why_it_matters = "Without adequate backups, data loss from deletion or corruption is unrecoverable."
    remediation = "Set backup retention period to at least 7 days."
    cli_fix = "aws rds modify-db-instance --db-instance-identifier <ID> --backup-retention-period 7"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for rds in resource.get("rds_instances", []):
            retention = rds.get("BackupRetentionPeriod", 0)
            if retention < 7:
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False,
                    resource_id=f"arn:aws:rds:us-east-1:db:{rds['DBInstanceIdentifier']}",
                    resource_type="AWS::RDS::DBInstance", region="us-east-1",
                    evidence={"DBInstance": rds["DBInstanceIdentifier"], "BackupRetentionPeriod": retention},
                    exposure=2, data_sensitivity_hint=3,
                ))
        return results


class BKP002EBSSnapshot(BaseCheck):
    check_id = "BKP-002"
    title = "EBS volumes with no snapshot"
    category = "Backup"
    severity = 2
    cis_control = "CIS 2.2.2"
    description = "EBS volumes should have at least one snapshot."
    why_it_matters = "Volumes without snapshots cannot be recovered after accidental deletion or failure."
    remediation = "Create snapshots for all EBS volumes or use AWS Backup."
    cli_fix = "aws ec2 create-snapshot --volume-id <VOLUME_ID> --description 'CloudShield backup'"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        snapshotted_volumes = {s["VolumeId"] for s in resource.get("ebs_snapshots", [])}
        for vol in resource.get("ebs_volumes", []):
            if vol["VolumeId"] not in snapshotted_volumes:
                tags = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False,
                    resource_id=f"arn:aws:ec2:us-east-1:volume/{vol['VolumeId']}",
                    resource_type="AWS::EC2::Volume", region="us-east-1",
                    evidence={"VolumeId": vol["VolumeId"], "HasSnapshot": False},
                    exposure=1, data_sensitivity_hint=2,
                    tags=tags,
                ))
        return results


ALL_NETWORK_CHECKS = [NET001SSH(), NET002RDP(), NET003DBPorts(), NET004DefaultSG()]
ALL_LOGGING_CHECKS = [LOG001CloudTrail(), LOG002Validation()]
ALL_ENCRYPTION_CHECKS = [ENC001EBSEncryption(), ENC002RDS(), ENC003KMSRotation()]
ALL_BACKUP_CHECKS = [BKP001RDSBackup(), BKP002EBSSnapshot()]
