"""IAM security checks: IAM-001 through IAM-008."""
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.checks.base import BaseCheck, CheckResult


def _utcnow():
    return datetime.now(timezone.utc)


def _days_since(date_str: str) -> int:
    try:
        if isinstance(date_str, datetime):
            dt = date_str.replace(tzinfo=timezone.utc) if date_str.tzinfo is None else date_str
        else:
            dt = datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))
        return (_utcnow() - dt).days
    except Exception:
        return 0


class IAM001RootMFA(BaseCheck):
    check_id = "IAM-001"
    title = "Root account has MFA enabled"
    category = "IAM"
    severity = 5
    cis_control = "CIS 1.5"
    description = "The root account should have MFA enabled."
    why_it_matters = "The root account has unrestricted access. If compromised without MFA, the attacker gains full control."
    remediation = "1. Sign in as root.\n2. Go to IAM → Security credentials.\n3. Enable MFA device."
    cli_fix = "# MFA cannot be enabled via CLI for root – use the AWS console."

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        if not resource.get("root_mfa_active", True):
            results.append(CheckResult(
                check_id=self.check_id, title=self.title, category=self.category,
                severity=self.severity, cis_control=self.cis_control,
                description=self.description, why_it_matters=self.why_it_matters,
                remediation=self.remediation, cli_fix=self.cli_fix,
                passed=False, resource_id="arn:aws:iam::ROOT", resource_type="AWS::IAM::Root",
                region="global", evidence={"root_mfa_active": False},
                exposure=5, data_sensitivity_hint=5,
            ))
        return results


class IAM002RootAccessKeys(BaseCheck):
    check_id = "IAM-002"
    title = "Root account has no active access keys"
    category = "IAM"
    severity = 5
    cis_control = "CIS 1.4"
    description = "The root account should not have active access keys."
    why_it_matters = "Root access keys cannot be restricted by IAM policies and should never exist."
    remediation = "1. Sign in as root.\n2. IAM → Security credentials → Delete all access keys."
    cli_fix = "aws iam delete-access-key --access-key-id <KEY_ID>"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        if resource.get("root_access_keys_active", False):
            results.append(CheckResult(
                check_id=self.check_id, title=self.title, category=self.category,
                severity=self.severity, cis_control=self.cis_control,
                description=self.description, why_it_matters=self.why_it_matters,
                remediation=self.remediation, cli_fix=self.cli_fix,
                passed=False, resource_id="arn:aws:iam::ROOT", resource_type="AWS::IAM::Root",
                region="global", evidence={"root_access_keys_active": True},
                exposure=5, data_sensitivity_hint=5,
            ))
        return results


class IAM003UserMFA(BaseCheck):
    check_id = "IAM-003"
    title = "IAM users with console password have MFA"
    category = "IAM"
    severity = 4
    cis_control = "CIS 1.10"
    description = "All IAM users with console access should have MFA enabled."
    why_it_matters = "Without MFA, a stolen password grants immediate console access."
    remediation = "1. IAM → Users → Select user → Security credentials → Assign MFA device."
    cli_fix = "# Use AWS console to assign MFA. CLI cannot configure virtual MFA interactively."

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for user in resource.get("users", []):
            if user.get("HasConsoleAccess") and not user.get("MFAActive"):
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False, resource_id=user["Arn"], resource_type="AWS::IAM::User",
                    region="global", evidence={"UserName": user["UserName"], "MFAActive": False},
                    exposure=4, data_sensitivity_hint=3,
                ))
        return results


class IAM004OldAccessKeys(BaseCheck):
    check_id = "IAM-004"
    title = "Access keys older than 90 days"
    category = "IAM"
    severity = 3
    cis_control = "CIS 1.14"
    description = "Access keys should be rotated every 90 days."
    why_it_matters = "Long-lived access keys increase the risk of credential compromise."
    remediation = "1. Create a new access key.\n2. Update applications.\n3. Deactivate and delete the old key."
    cli_fix = "aws iam create-access-key --user-name <USERNAME>\naws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_KEY_ID>"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for user in resource.get("users", []):
            for key in user.get("AccessKeys", []):
                if key.get("Status") == "Active":
                    age_days = _days_since(key.get("CreateDate", ""))
                    if age_days > 90:
                        results.append(CheckResult(
                            check_id=self.check_id, title=self.title, category=self.category,
                            severity=self.severity, cis_control=self.cis_control,
                            description=self.description, why_it_matters=self.why_it_matters,
                            remediation=self.remediation, cli_fix=self.cli_fix,
                            passed=False, resource_id=user["Arn"], resource_type="AWS::IAM::User",
                            region="global",
                            evidence={"UserName": user["UserName"], "AccessKeyId": key["AccessKeyId"], "AgeDays": age_days},
                            exposure=3, data_sensitivity_hint=3,
                        ))
        return results


class IAM005UnusedCredentials(BaseCheck):
    check_id = "IAM-005"
    title = "Unused credentials (no activity 90+ days)"
    category = "IAM"
    severity = 3
    cis_control = "CIS 1.12"
    description = "IAM credentials unused for 90+ days should be disabled."
    why_it_matters = "Dormant credentials are a silent attack surface – attackers can use them without detection."
    remediation = "1. Identify unused credentials.\n2. Disable or delete the access key or console password."
    cli_fix = "aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Inactive"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for user in resource.get("users", []):
            last_used = user.get("PasswordLastUsed")
            if last_used:
                days = _days_since(last_used)
                if days > 90:
                    results.append(CheckResult(
                        check_id=self.check_id, title=self.title, category=self.category,
                        severity=self.severity, cis_control=self.cis_control,
                        description=self.description, why_it_matters=self.why_it_matters,
                        remediation=self.remediation, cli_fix=self.cli_fix,
                        passed=False, resource_id=user["Arn"], resource_type="AWS::IAM::User",
                        region="global",
                        evidence={"UserName": user["UserName"], "LastUsedDays": days},
                        exposure=2, data_sensitivity_hint=3,
                    ))
        return results


class IAM006StarPolicy(BaseCheck):
    check_id = "IAM-006"
    title = "Policies allowing Action:* on Resource:*"
    category = "IAM"
    severity = 5
    cis_control = "CIS 1.16"
    description = "No IAM policy should grant Action:* on Resource:*."
    why_it_matters = "This is effectively a superuser grant. One compromised identity = full account takeover."
    remediation = "1. Replace wildcard policies with least-privilege policies.\n2. Use IAM Access Analyzer."
    cli_fix = "aws iam detach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for user in resource.get("users", []):
            # Check inline policies
            for policy in user.get("InlinePolicies", []):
                doc = policy.get("PolicyDocument", {})
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        actions = stmt.get("Action", [])
                        resources = stmt.get("Resource", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]
                        if "*" in actions and "*" in resources:
                            results.append(CheckResult(
                                check_id=self.check_id, title=self.title, category=self.category,
                                severity=self.severity, cis_control=self.cis_control,
                                description=self.description, why_it_matters=self.why_it_matters,
                                remediation=self.remediation, cli_fix=self.cli_fix,
                                passed=False, resource_id=user["Arn"], resource_type="AWS::IAM::User",
                                region="global",
                                evidence={"UserName": user["UserName"], "PolicyName": policy["PolicyName"], "Statement": stmt},
                                exposure=4, data_sensitivity_hint=5,
                            ))
        return results


class IAM007DirectPolicy(BaseCheck):
    check_id = "IAM-007"
    title = "IAM users with directly attached policies"
    category = "IAM"
    severity = 2
    cis_control = "CIS 1.15"
    description = "Permissions should be assigned through groups/roles, not directly to users."
    why_it_matters = "Direct policy attachments make permission management complex and error-prone."
    remediation = "1. Create IAM groups with appropriate policies.\n2. Add users to groups.\n3. Remove direct policy attachments."
    cli_fix = "aws iam detach-user-policy --user-name <USERNAME> --policy-arn <POLICY_ARN>"

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        for user in resource.get("users", []):
            attached = user.get("AttachedPolicies", [])
            if attached:
                results.append(CheckResult(
                    check_id=self.check_id, title=self.title, category=self.category,
                    severity=self.severity, cis_control=self.cis_control,
                    description=self.description, why_it_matters=self.why_it_matters,
                    remediation=self.remediation, cli_fix=self.cli_fix,
                    passed=False, resource_id=user["Arn"], resource_type="AWS::IAM::User",
                    region="global",
                    evidence={"UserName": user["UserName"], "AttachedPolicies": attached},
                    exposure=1, data_sensitivity_hint=2,
                ))
        return results


class IAM008PasswordPolicy(BaseCheck):
    check_id = "IAM-008"
    title = "Account password policy meets minimum requirements"
    category = "IAM"
    severity = 3
    cis_control = "CIS 1.8"
    description = "Password policy should enforce length ≥14, rotation, and prevent reuse."
    why_it_matters = "Weak password policies allow brute-force attacks."
    remediation = "1. IAM → Account settings → Set password policy.\n2. Enforce length ≥ 14, rotation ≤ 90 days, prevent last 24 passwords."
    cli_fix = 'aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols --max-password-age 90 --password-reuse-prevention 24'

    def evaluate(self, resource: Dict) -> List[CheckResult]:
        results = []
        policy = resource.get("account_password_policy", {})
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append(f"Min length {policy.get('MinimumPasswordLength', 0)} < 14")
        if not policy.get("ExpirePasswords"):
            issues.append("Password expiry not configured")
        if policy.get("PasswordReusePrevention", 0) < 5:
            issues.append("Password reuse prevention < 5")

        if issues:
            results.append(CheckResult(
                check_id=self.check_id, title=self.title, category=self.category,
                severity=self.severity, cis_control=self.cis_control,
                description=self.description, why_it_matters=self.why_it_matters,
                remediation=self.remediation, cli_fix=self.cli_fix,
                passed=False, resource_id="arn:aws:iam::ACCOUNT:password-policy",
                resource_type="AWS::IAM::PasswordPolicy",
                region="global", evidence={"Issues": issues, "Policy": policy},
                exposure=3, data_sensitivity_hint=3,
            ))
        return results


ALL_IAM_CHECKS = [
    IAM001RootMFA(),
    IAM002RootAccessKeys(),
    IAM003UserMFA(),
    IAM004OldAccessKeys(),
    IAM005UnusedCredentials(),
    IAM006StarPolicy(),
    IAM007DirectPolicy(),
    IAM008PasswordPolicy(),
]
