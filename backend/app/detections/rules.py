"""CloudTrail detection rules – 10 rules as per PRD Section 7.3."""
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


def _get_user(event: Dict) -> Tuple[str, str]:
    identity = event.get("userIdentity", {})
    username = identity.get("userName") or identity.get("type", "Unknown")
    arn = identity.get("arn", "")
    return username, arn


def _get_source_ip(event: Dict) -> str:
    return event.get("sourceIPAddress", "unknown")


def _get_event_name(event: Dict) -> str:
    return event.get("eventName", "")


def _get_region(event: Dict) -> str:
    return event.get("awsRegion", "us-east-1")


class DetectionRule:
    rule_id: str = ""
    title: str = ""
    severity: str = "medium"  # critical | high | medium | low

    def matches(self, event: Dict) -> bool:
        return False

    def get_title(self, event: Dict) -> str:
        return self.title


class DET001ConsoleLoginNoMFA(DetectionRule):
    rule_id = "DET-001"
    title = "Console login without MFA"
    severity = "high"

    def matches(self, event: Dict) -> bool:
        if _get_event_name(event) != "ConsoleLogin":
            return False
        additional = event.get("additionalEventData", {})
        if isinstance(additional, str):
            return False
        mfa_used = additional.get("MFAUsed", "Yes")
        response = event.get("responseElements", {})
        login_result = response.get("ConsoleLogin", "") if isinstance(response, dict) else ""
        return mfa_used == "No" and login_result == "Success"

    def get_title(self, event: Dict) -> str:
        username, _ = _get_user(event)
        return f"Console login without MFA: {username}"


class DET002RootUsed(DetectionRule):
    rule_id = "DET-002"
    title = "Root account used"
    severity = "critical"

    def matches(self, event: Dict) -> bool:
        identity = event.get("userIdentity", {})
        return identity.get("type") == "Root"

    def get_title(self, event: Dict) -> str:
        return f"Root account used for {_get_event_name(event)}"


class DET003NewAccessKey(DetectionRule):
    rule_id = "DET-003"
    title = "New access key created"
    severity = "medium"

    def matches(self, event: Dict) -> bool:
        return _get_event_name(event) == "CreateAccessKey"

    def get_title(self, event: Dict) -> str:
        username, _ = _get_user(event)
        params = event.get("requestParameters", {})
        target = params.get("userName", "unknown") if isinstance(params, dict) else "unknown"
        return f"Access key created for {target} by {username}"


class DET004CloudTrailStopped(DetectionRule):
    rule_id = "DET-004"
    title = "CloudTrail stopped or deleted"
    severity = "critical"
    _events = {"StopLogging", "DeleteTrail", "UpdateTrail"}

    def matches(self, event: Dict) -> bool:
        return _get_event_name(event) in self._events

    def get_title(self, event: Dict) -> str:
        return f"CloudTrail {_get_event_name(event)} detected"


class DET005SGOpenedToInternet(DetectionRule):
    rule_id = "DET-005"
    title = "Security group opened to internet"
    severity = "high"

    def matches(self, event: Dict) -> bool:
        if _get_event_name(event) != "AuthorizeSecurityGroupIngress":
            return False
        params = event.get("requestParameters", {})
        if not isinstance(params, dict):
            return False
        perms = params.get("ipPermissions", {})
        items = perms.get("items", []) if isinstance(perms, dict) else []
        for perm in items:
            for ip_range in perm.get("ipRanges", {}).get("items", []):
                if ip_range.get("cidrIp") in ("0.0.0.0/0", "::/0"):
                    return True
        return False

    def get_title(self, event: Dict) -> str:
        params = event.get("requestParameters", {})
        sg_id = params.get("groupId", "unknown") if isinstance(params, dict) else "unknown"
        return f"Security group {sg_id} opened to internet"


class DET006S3MadePublic(DetectionRule):
    rule_id = "DET-006"
    title = "S3 bucket made public or public access block removed"
    severity = "critical"
    _events = {"DeleteBucketPublicAccessBlock", "PutBucketAcl", "PutBucketPolicy"}

    def matches(self, event: Dict) -> bool:
        return _get_event_name(event) in self._events

    def get_title(self, event: Dict) -> str:
        params = event.get("requestParameters", {})
        bucket = params.get("bucketName", "unknown") if isinstance(params, dict) else "unknown"
        return f"S3 bucket {bucket} public access modified: {_get_event_name(event)}"


class DET007AdminPrivileges(DetectionRule):
    rule_id = "DET-007"
    title = "Admin privileges granted"
    severity = "high"
    _events = {"AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy"}

    def matches(self, event: Dict) -> bool:
        if _get_event_name(event) not in self._events:
            return False
        params = event.get("requestParameters", {})
        if not isinstance(params, dict):
            return False
        policy_arn = params.get("policyArn", "")
        return "AdministratorAccess" in policy_arn or "AdministratorAccess" in str(params)

    def get_title(self, event: Dict) -> str:
        username, _ = _get_user(event)
        params = event.get("requestParameters", {})
        target = params.get("userName", params.get("roleName", "unknown")) if isinstance(params, dict) else "unknown"
        return f"Admin privileges granted to {target} by {username}"


class DET008MultipleFailedLogins(DetectionRule):
    """Stateless version – flags each individual failed login. Full implementation requires state."""
    rule_id = "DET-008"
    title = "Failed console login attempt"
    severity = "medium"

    def matches(self, event: Dict) -> bool:
        if _get_event_name(event) != "ConsoleLogin":
            return False
        response = event.get("responseElements", {})
        login_result = response.get("ConsoleLogin", "") if isinstance(response, dict) else ""
        return login_result == "Failure"

    def get_title(self, event: Dict) -> str:
        username, _ = _get_user(event)
        ip = _get_source_ip(event)
        return f"Failed console login: {username} from {ip}"


class DET009MFADeactivated(DetectionRule):
    rule_id = "DET-009"
    title = "MFA device deactivated or deleted"
    severity = "high"
    _events = {"DeactivateMFADevice", "DeleteVirtualMFADevice"}

    def matches(self, event: Dict) -> bool:
        return _get_event_name(event) in self._events

    def get_title(self, event: Dict) -> str:
        username, _ = _get_user(event)
        params = event.get("requestParameters", {})
        target = params.get("userName", "unknown") if isinstance(params, dict) else "unknown"
        return f"MFA deactivated for {target} by {username}"


class DET010NewIPLogin(DetectionRule):
    rule_id = "DET-010"
    title = "Login from new IP address"
    severity = "low"

    def matches(self, event: Dict) -> bool:
        # Stateless: flag all successful console logins with a non-RFC1918 IP
        if _get_event_name(event) != "ConsoleLogin":
            return False
        response = event.get("responseElements", {})
        login_result = response.get("ConsoleLogin", "") if isinstance(response, dict) else ""
        if login_result != "Success":
            return False
        ip = _get_source_ip(event)
        # flag non-internal IPs as "potentially new"
        return not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."))

    def get_title(self, event: Dict) -> str:
        username, _ = _get_user(event)
        ip = _get_source_ip(event)
        return f"Console login from external IP {ip}: {username}"


ALL_RULES = [
    DET001ConsoleLoginNoMFA(),
    DET002RootUsed(),
    DET003NewAccessKey(),
    DET004CloudTrailStopped(),
    DET005SGOpenedToInternet(),
    DET006S3MadePublic(),
    DET007AdminPrivileges(),
    DET008MultipleFailedLogins(),
    DET009MFADeactivated(),
    DET010NewIPLogin(),
]


def evaluate_event(event: Dict) -> List[DetectionRule]:
    """Return all rules that match this CloudTrail event."""
    return [rule for rule in ALL_RULES if rule.matches(event)]
