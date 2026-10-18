"""Pydantic v2 schemas for CloudShield API."""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, EmailStr, field_validator
from app.models import (
    UserRole, AccountProvider, AccountStatus, ScanStatus,
    FindingStatus, FindingDiffState, AlertStatus, AlertSeverity
)


# ─── Auth ────────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    email: str


class UserOut(BaseModel):
    id: int
    email: str
    role: UserRole
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Accounts ────────────────────────────────────────────────────────────────
class AccountCreate(BaseModel):
    name: str
    provider: AccountProvider = AccountProvider.aws
    region: str = "us-east-1"
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    assume_role_arn: Optional[str] = None
    is_demo: bool = False


class AccountOut(BaseModel):
    id: int
    name: str
    provider: AccountProvider
    region: str
    account_id: Optional[str]
    auth_type: str
    is_demo: bool
    status: AccountStatus
    created_at: datetime
    last_scan_at: Optional[datetime]

    model_config = {"from_attributes": True}


class TestConnectionResponse(BaseModel):
    success: bool
    account_id: Optional[str] = None
    message: str


# ─── Scans ───────────────────────────────────────────────────────────────────
class ScanStart(BaseModel):
    account_id: int


class ScanOut(BaseModel):
    id: int
    account_id: int
    status: ScanStatus
    started_at: datetime
    finished_at: Optional[datetime]
    total_resources: int
    total_findings: int
    account_risk_score: float
    summary_json: Optional[str]

    model_config = {"from_attributes": True}


# ─── Findings ────────────────────────────────────────────────────────────────
class FindingOut(BaseModel):
    id: int
    scan_id: int
    account_id: int
    check_id: str
    title: str
    category: str
    resource_id: str
    resource_type: str
    region: Optional[str]
    severity: int
    exposure: int
    data_sensitivity: int
    risk_score: int
    band: str
    evidence_json: Optional[str]
    cis_control: Optional[str]
    remediation: Optional[str]
    cli_fix: Optional[str]
    status: FindingStatus
    note: Optional[str]
    diff_state: Optional[FindingDiffState]
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None
    note: Optional[str] = None
    data_sensitivity: Optional[int] = None


class BulkStatusUpdate(BaseModel):
    finding_ids: List[int]
    status: FindingStatus
    note: Optional[str] = None


# ─── Alerts ──────────────────────────────────────────────────────────────────
class AlertOut(BaseModel):
    id: int
    account_id: int
    event_id: Optional[int]
    rule_id: str
    title: str
    severity: AlertSeverity
    status: AlertStatus
    note: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    note: Optional[str] = None


# ─── Events ──────────────────────────────────────────────────────────────────
class EventOut(BaseModel):
    id: int
    account_id: int
    event_time: datetime
    event_name: str
    event_source: Optional[str]
    username: Optional[str]
    user_arn: Optional[str]
    source_ip: Optional[str]
    region: Optional[str]
    raw_json: Optional[str]

    model_config = {"from_attributes": True}


# ─── IaC ─────────────────────────────────────────────────────────────────────
class IacFindingOut(BaseModel):
    id: int
    iac_scan_id: int
    check_id: Optional[str]
    check_name: Optional[str]
    file_path: Optional[str]
    line_start: Optional[int]
    line_end: Optional[int]
    resource: Optional[str]
    severity: int
    exposure: int
    data_sensitivity: int
    risk_score: int
    guideline: Optional[str]

    model_config = {"from_attributes": True}


class IacScanOut(BaseModel):
    id: int
    user_id: int
    created_at: datetime
    verdict: Optional[str]
    summary_json: Optional[str]
    findings: List[IacFindingOut] = []

    model_config = {"from_attributes": True}


# ─── Dashboard ───────────────────────────────────────────────────────────────
class DashboardSummary(BaseModel):
    account_risk_score: float
    total_open: int
    critical: int
    high: int
    medium: int
    low: int
    by_category: Dict[str, int]
    compliance_pct: Dict[str, float]
    top5_risks: List[FindingOut]
    recent_alerts: List[AlertOut]
    last_scan: Optional[ScanOut]


class TrendPoint(BaseModel):
    scan_id: int
    started_at: datetime
    account_risk_score: float
    total_findings: int


# ─── Settings ────────────────────────────────────────────────────────────────
class SettingUpdate(BaseModel):
    value_json: Any


# ─── Pagination ──────────────────────────────────────────────────────────────
class PaginatedFindings(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[FindingOut]
