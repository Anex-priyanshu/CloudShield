"""AWS resource collector using boto3 read-only calls."""
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _make_session(credentials: dict, region: str):
    import boto3
    if credentials.get("assume_role_arn"):
        sts = boto3.client(
            "sts",
            aws_access_key_id=credentials.get("access_key_id"),
            aws_secret_access_key=credentials.get("secret_access_key"),
            region_name=region,
        )
        assumed = sts.assume_role(
            RoleArn=credentials["assume_role_arn"],
            RoleSessionName="CloudShieldReadOnly",
        )
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
    return boto3.Session(
        aws_access_key_id=credentials.get("access_key_id"),
        aws_secret_access_key=credentials.get("secret_access_key"),
        region_name=region,
    )


def collect_iam(session) -> dict:
    """Collect IAM data: root status, users, password policy."""
    iam = session.client("iam")
    result = {}

    # Root info via credential report
    try:
        iam.generate_credential_report()
        import time; time.sleep(2)
        report = iam.get_credential_report()
        lines = report["Content"].decode().split("\n")
        headers = lines[0].split(",")
        for line in lines[1:]:
            if not line:
                continue
            cols = dict(zip(headers, line.split(",")))
            if cols.get("user") == "<root_account>":
                result["root_mfa_active"] = cols.get("mfa_active", "false").lower() == "true"
                result["root_access_keys_active"] = (
                    cols.get("access_key_1_active", "false").lower() == "true" or
                    cols.get("access_key_2_active", "false").lower() == "true"
                )
    except Exception as e:
        logger.warning(f"IAM credential report failed: {e}")
        result["root_mfa_active"] = True  # Assume safe if we can't check
        result["root_access_keys_active"] = False

    # Password policy
    try:
        pp = iam.get_account_password_policy()["PasswordPolicy"]
        result["account_password_policy"] = pp
    except Exception:
        result["account_password_policy"] = {}

    # Users
    users = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page["Users"]:
                user_data = {
                    "UserName": u["UserName"],
                    "UserId": u["UserId"],
                    "Arn": u["Arn"],
                    "CreateDate": u["CreateDate"].isoformat(),
                    "PasswordLastUsed": u.get("PasswordLastUsed", ""),
                    "MFAActive": False,
                    "HasConsoleAccess": False,
                    "AccessKeys": [],
                    "AttachedPolicies": [],
                    "InlinePolicies": [],
                }
                # Check console access
                try:
                    iam.get_login_profile(UserName=u["UserName"])
                    user_data["HasConsoleAccess"] = True
                except Exception:
                    pass
                # MFA
                try:
                    mfa = iam.list_mfa_devices(UserName=u["UserName"])
                    user_data["MFAActive"] = len(mfa["MFADevices"]) > 0
                except Exception:
                    pass
                # Access keys
                try:
                    keys = iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]
                    for k in keys:
                        last_used = ""
                        try:
                            lu = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])
                            last_used = lu.get("AccessKeyLastUsed", {}).get("LastUsedDate", "")
                            if last_used:
                                last_used = last_used.isoformat()
                        except Exception:
                            pass
                        user_data["AccessKeys"].append({
                            "AccessKeyId": k["AccessKeyId"],
                            "Status": k["Status"],
                            "CreateDate": k["CreateDate"].isoformat(),
                            "LastUsedDate": last_used,
                        })
                except Exception:
                    pass
                # Attached policies
                try:
                    attached = iam.list_attached_user_policies(UserName=u["UserName"])["AttachedPolicies"]
                    user_data["AttachedPolicies"] = [p["PolicyName"] for p in attached]
                except Exception:
                    pass
                # Inline policies
                try:
                    inline_names = iam.list_user_policies(UserName=u["UserName"])["PolicyNames"]
                    for pname in inline_names:
                        policy_doc = iam.get_user_policy(UserName=u["UserName"], PolicyName=pname)
                        user_data["InlinePolicies"].append({
                            "PolicyName": pname,
                            "PolicyDocument": policy_doc["PolicyDocument"],
                        })
                except Exception:
                    pass
                users.append(user_data)
    except Exception as e:
        logger.warning(f"IAM users collection failed: {e}")

    result["users"] = users
    return result


def collect_s3(session) -> dict:
    """Collect S3 bucket data."""
    s3 = session.client("s3")
    s3control = session.client("s3control", region_name="us-east-1")
    result = {"s3_buckets": [], "account_level_public_access_block": True}

    try:
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        pab = s3control.get_public_access_block(AccountId=account_id)
        cfg = pab.get("PublicAccessBlockConfiguration", {})
        result["account_level_public_access_block"] = all([
            cfg.get("BlockPublicAcls", False),
            cfg.get("BlockPublicPolicy", False),
            cfg.get("IgnorePublicAcls", False),
            cfg.get("RestrictPublicBuckets", False),
        ])
    except Exception as e:
        logger.warning(f"Account BPA check failed: {e}")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            name = b["Name"]
            bdata = {"Name": name, "Region": "us-east-1", "ACL": "private",
                     "PublicAccessBlock": None, "Encryption": None,
                     "Versioning": False, "LoggingEnabled": False, "HttpsEnforced": False, "Tags": {}}
            try:
                loc = s3.get_bucket_location(Bucket=name)
                bdata["Region"] = loc.get("LocationConstraint") or "us-east-1"
            except Exception:
                pass
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI") in [
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                    ]:
                        bdata["ACL"] = "public-read"
                        break
            except Exception:
                pass
            try:
                pab = s3.get_public_access_block(Bucket=name)
                bdata["PublicAccessBlock"] = pab["PublicAccessBlockConfiguration"]
            except Exception:
                pass
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    bdata["Encryption"] = rules[0].get("ApplyServerSideEncryptionByDefault")
            except Exception:
                pass
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                bdata["Versioning"] = ver.get("Status") == "Enabled"
            except Exception:
                pass
            try:
                log = s3.get_bucket_logging(Bucket=name)
                bdata["LoggingEnabled"] = "LoggingEnabled" in log
            except Exception:
                pass
            try:
                tags_response = s3.get_bucket_tagging(Bucket=name)
                bdata["Tags"] = {t["Key"]: t["Value"] for t in tags_response.get("TagSet", [])}
            except Exception:
                pass
            result["s3_buckets"].append(bdata)
    except Exception as e:
        logger.warning(f"S3 collection failed: {e}")

    return result


def collect_ec2(session) -> dict:
    """Collect EC2 security groups."""
    ec2 = session.client("ec2")
    result = {"security_groups": []}
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                result["security_groups"].append({
                    "GroupId": sg["GroupId"],
                    "GroupName": sg.get("GroupName", ""),
                    "VpcId": sg.get("VpcId", ""),
                    "IpPermissions": sg.get("IpPermissions", []),
                })
    except Exception as e:
        logger.warning(f"EC2 SG collection failed: {e}")
    return result


def collect_cloudtrail(session) -> dict:
    """Collect CloudTrail trail status."""
    ct = session.client("cloudtrail")
    result = {"cloudtrail_trails": []}
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        for trail in trails:
            status = {}
            try:
                status = ct.get_trail_status(Name=trail["TrailARN"])
            except Exception:
                pass
            result["cloudtrail_trails"].append({
                "TrailARN": trail.get("TrailARN"),
                "IsMultiRegionTrail": trail.get("IsMultiRegionTrail", False),
                "LogFileValidationEnabled": trail.get("LogFileValidationEnabled", False),
                "IsLogging": status.get("IsLogging", False),
                "HomeRegion": trail.get("HomeRegion", ""),
            })
    except Exception as e:
        logger.warning(f"CloudTrail collection failed: {e}")
    return result


def collect_ebs(session) -> dict:
    """Collect EBS volumes and snapshots."""
    ec2 = session.client("ec2")
    result = {"ebs_volumes": [], "ebs_snapshots": []}
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                result["ebs_volumes"].append({
                    "VolumeId": vol["VolumeId"],
                    "Encrypted": vol.get("Encrypted", False),
                    "Size": vol.get("Size", 0),
                    "Tags": vol.get("Tags", []),
                })
    except Exception as e:
        logger.warning(f"EBS volume collection failed: {e}")
    try:
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=[account_id]):
            for snap in page["Snapshots"]:
                result["ebs_snapshots"].append({
                    "VolumeId": snap.get("VolumeId", ""),
                    "SnapshotId": snap["SnapshotId"],
                })
    except Exception as e:
        logger.warning(f"EBS snapshot collection failed: {e}")
    return result


def collect_rds(session) -> dict:
    """Collect RDS instances."""
    rds = session.client("rds")
    result = {"rds_instances": []}
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                result["rds_instances"].append({
                    "DBInstanceIdentifier": db["DBInstanceIdentifier"],
                    "DBInstanceClass": db.get("DBInstanceClass", ""),
                    "Engine": db.get("Engine", ""),
                    "StorageEncrypted": db.get("StorageEncrypted", False),
                    "PubliclyAccessible": db.get("PubliclyAccessible", False),
                    "BackupRetentionPeriod": db.get("BackupRetentionPeriod", 0),
                    "MultiAZ": db.get("MultiAZ", False),
                    "Tags": db.get("TagList", []),
                })
    except Exception as e:
        logger.warning(f"RDS collection failed: {e}")
    return result


def collect_kms(session) -> dict:
    """Collect KMS customer-managed keys."""
    kms = session.client("kms")
    result = {"kms_keys": []}
    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key_ref in page["Keys"]:
                try:
                    meta = kms.describe_key(KeyId=key_ref["KeyId"])["KeyMetadata"]
                    if meta.get("KeyManager") != "CUSTOMER":
                        continue
                    rotation = False
                    try:
                        rot = kms.get_key_rotation_status(KeyId=key_ref["KeyId"])
                        rotation = rot.get("KeyRotationEnabled", False)
                    except Exception:
                        pass
                    result["kms_keys"].append({
                        "KeyId": meta["KeyId"],
                        "KeyArn": meta["Arn"],
                        "Description": meta.get("Description", ""),
                        "KeyManager": meta.get("KeyManager", ""),
                        "KeyState": meta.get("KeyState", ""),
                        "RotationEnabled": rotation,
                    })
                except Exception as e:
                    logger.warning(f"KMS key {key_ref['KeyId']} failed: {e}")
    except Exception as e:
        logger.warning(f"KMS collection failed: {e}")
    return result


def collect_all(credentials: dict, region: str) -> dict:
    """Collect all resources from a real AWS account."""
    session = _make_session(credentials, region)
    result = {}

    collectors = [
        ("IAM", lambda: {"iam": collect_iam(session)}),
        ("S3", lambda: collect_s3(session)),
        ("EC2", lambda: collect_ec2(session)),
        ("CloudTrail", lambda: collect_cloudtrail(session)),
        ("EBS", lambda: collect_ebs(session)),
        ("RDS", lambda: collect_rds(session)),
        ("KMS", lambda: collect_kms(session)),
    ]

    for name, collector in collectors:
        try:
            data = collector()
            result.update(data)
        except Exception as e:
            logger.error(f"Collector {name} failed entirely: {e}")

    return result


def test_connection(credentials: dict, region: str) -> dict:
    """Test AWS connection using STS GetCallerIdentity."""
    import boto3
    try:
        session = _make_session(credentials, region)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        return {"success": True, "account_id": identity["Account"], "message": f"Connected as {identity['Arn']}"}
    except Exception as e:
        return {"success": False, "account_id": None, "message": str(e)}
