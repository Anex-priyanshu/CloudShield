"""Demo CloudTrail event generator – produces realistic fake events every few seconds."""
import asyncio
import json
import random
from datetime import datetime, timezone
from typing import Optional

DEMO_EVENTS = [
    {
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "userIdentity": {"type": "IAMUser", "userName": "alice-admin", "arn": "arn:aws:iam::123456789012:user/alice-admin"},
        "sourceIPAddress": "203.0.113.1",
        "awsRegion": "us-east-1",
        "additionalEventData": {"MFAUsed": "No"},
        "responseElements": {"ConsoleLogin": "Success"},
    },
    {
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
        "sourceIPAddress": "198.51.100.5",
        "awsRegion": "us-east-1",
        "additionalEventData": {"MFAUsed": "No"},
        "responseElements": {"ConsoleLogin": "Success"},
    },
    {
        "eventName": "CreateAccessKey",
        "eventSource": "iam.amazonaws.com",
        "userIdentity": {"type": "IAMUser", "userName": "alice-admin", "arn": "arn:aws:iam::123456789012:user/alice-admin"},
        "sourceIPAddress": "203.0.113.1",
        "awsRegion": "us-east-1",
        "requestParameters": {"userName": "bob-developer"},
    },
    {
        "eventName": "AuthorizeSecurityGroupIngress",
        "eventSource": "ec2.amazonaws.com",
        "userIdentity": {"type": "IAMUser", "userName": "david-devops", "arn": "arn:aws:iam::123456789012:user/david-devops"},
        "sourceIPAddress": "203.0.113.55",
        "awsRegion": "us-east-1",
        "requestParameters": {
            "groupId": "sg-00001",
            "ipPermissions": {"items": [{"fromPort": 22, "toPort": 22, "ipProtocol": "tcp", "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}
        },
    },
    {
        "eventName": "DeleteBucketPublicAccessBlock",
        "eventSource": "s3.amazonaws.com",
        "userIdentity": {"type": "IAMUser", "userName": "alice-admin", "arn": "arn:aws:iam::123456789012:user/alice-admin"},
        "sourceIPAddress": "203.0.113.1",
        "awsRegion": "us-east-1",
        "requestParameters": {"bucketName": "customer-data-prod"},
    },
    {
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "userIdentity": {"type": "IAMUser", "userName": "alice-admin", "arn": "arn:aws:iam::123456789012:user/alice-admin"},
        "sourceIPAddress": "203.0.113.1",
        "awsRegion": "us-east-1",
        "requestParameters": {"name": "main-trail"},
    },
    {
        "eventName": "DescribeInstances",
        "eventSource": "ec2.amazonaws.com",
        "userIdentity": {"type": "IAMUser", "userName": "bob-developer", "arn": "arn:aws:iam::123456789012:user/bob-developer"},
        "sourceIPAddress": "203.0.113.10",
        "awsRegion": "us-east-1",
        "requestParameters": {},
    },
    {
        "eventName": "ListBuckets",
        "eventSource": "s3.amazonaws.com",
        "userIdentity": {"type": "IAMUser", "userName": "carol-viewer", "arn": "arn:aws:iam::123456789012:user/carol-viewer"},
        "sourceIPAddress": "172.16.0.5",
        "awsRegion": "us-east-1",
        "requestParameters": {},
    },
    {
        "eventName": "AttachUserPolicy",
        "eventSource": "iam.amazonaws.com",
        "userIdentity": {"type": "IAMUser", "userName": "alice-admin", "arn": "arn:aws:iam::123456789012:user/alice-admin"},
        "sourceIPAddress": "203.0.113.1",
        "awsRegion": "us-east-1",
        "requestParameters": {"userName": "frank-intern", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    },
    {
        "eventName": "DeactivateMFADevice",
        "eventSource": "iam.amazonaws.com",
        "userIdentity": {"type": "IAMUser", "userName": "alice-admin", "arn": "arn:aws:iam::123456789012:user/alice-admin"},
        "sourceIPAddress": "203.0.113.1",
        "awsRegion": "us-east-1",
        "requestParameters": {"userName": "grace-analyst", "serialNumber": "arn:aws:iam::123456789012:mfa/grace-analyst"},
    },
    {
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "userIdentity": {"type": "IAMUser", "userName": "bob-developer", "arn": "arn:aws:iam::123456789012:user/bob-developer"},
        "sourceIPAddress": "45.76.100.200",
        "awsRegion": "us-east-1",
        "additionalEventData": {"MFAUsed": "Yes"},
        "responseElements": {"ConsoleLogin": "Success"},
    },
    {
        "eventName": "GetObject",
        "eventSource": "s3.amazonaws.com",
        "userIdentity": {"type": "IAMUser", "userName": "grace-analyst", "arn": "arn:aws:iam::123456789012:user/grace-analyst"},
        "sourceIPAddress": "10.0.1.5",
        "awsRegion": "us-east-1",
        "requestParameters": {"bucketName": "app-access-logs", "key": "2026/10/access.log"},
    },
]

# Events that match detection rules (roughly 1 in 6)
RULE_EVENTS = [
    DEMO_EVENTS[0],  # DET-001: Console login without MFA
    DEMO_EVENTS[1],  # DET-002: Root account used
    DEMO_EVENTS[2],  # DET-003: New access key
    DEMO_EVENTS[3],  # DET-005: SG opened to internet
    DEMO_EVENTS[4],  # DET-006: S3 public block removed
    DEMO_EVENTS[5],  # DET-004: CloudTrail stopped
    DEMO_EVENTS[8],  # DET-007: Admin policy attached
    DEMO_EVENTS[9],  # DET-009: MFA deactivated
]

NORMAL_EVENTS = [e for e in DEMO_EVENTS if e not in RULE_EVENTS]


def generate_demo_event() -> dict:
    """Pick a random event – roughly 1 in 6 will be a rule-matching event."""
    if random.random() < (1 / 6):
        base = random.choice(RULE_EVENTS)
    else:
        base = random.choice(NORMAL_EVENTS)

    event = base.copy()
    event["eventTime"] = datetime.now(timezone.utc).isoformat()
    event["eventID"] = f"demo-{random.randint(100000, 999999)}"
    return event
