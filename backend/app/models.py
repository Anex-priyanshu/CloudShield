"""SQLAlchemy ORM models for CloudShield."""
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Float, Text,
    ForeignKey, Enum as SAEnum
)
from sqlalchemy.orm import relationship
import enum

from app.db import Base


class UserRole(str, enum.Enum):
    admin = "admin"
    viewer = "viewer"


class AccountProvider(str, enum.Enum):
    aws = "aws"
    demo = "demo"


class AccountStatus(str, enum.Enum):
    connected = "connected"
    error = "error"
    demo = "demo"


class ScanStatus(str, enum.Enum):
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class FindingStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    fixed = "fixed"
    false_positive = "false_positive"


class FindingDiffState(str, enum.Enum):
    new = "new"
    existing = "existing"
    fixed = "fixed"


class AlertStatus(str, enum.Enum):
    new = "new"
    investigating = "investigating"
    resolved = "resolved"
    false_positive = "false_positive"


class AlertSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


# ─── Users ───────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(SAEnum(UserRole), default=UserRole.viewer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    iac_scans = relationship("IacScan", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")


# ─── Cloud Accounts ───────────────────────────────────────────────────────────
class CloudAccount(Base):
    __tablename__ = "cloud_accounts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    provider = Column(SAEnum(AccountProvider), default=AccountProvider.aws, nullable=False)
    region = Column(String(64), default="us-east-1")
    account_id = Column(String(64), nullable=True)  # AWS account ID discovered on test
    auth_type = Column(String(32), default="access_key")  # access_key | assume_role
    credentials_encrypted = Column(Text, nullable=True)  # Fernet-encrypted JSON
    is_demo = Column(Boolean, default=False)
    status = Column(SAEnum(AccountStatus), default=AccountStatus.connected, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_scan_at = Column(DateTime, nullable=True)

    scans = relationship("Scan", back_populates="account")
    findings = relationship("Finding", back_populates="account")
    events = relationship("Event", back_populates="account")
    alerts = relationship("Alert", back_populates="account")
    overrides = relationship("ResourceOverride", back_populates="account")


# ─── Scans ────────────────────────────────────────────────────────────────────
class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("cloud_accounts.id"), nullable=False)
    status = Column(SAEnum(ScanStatus), default=ScanStatus.running, nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    total_resources = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    account_risk_score = Column(Float, default=0.0)
    summary_json = Column(Text, nullable=True)  # JSON string

    account = relationship("CloudAccount", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")


# ─── Findings ─────────────────────────────────────────────────────────────────
class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    account_id = Column(Integer, ForeignKey("cloud_accounts.id"), nullable=False)
    check_id = Column(String(32), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    category = Column(String(64), nullable=False, index=True)
    resource_id = Column(String(512), nullable=False)
    resource_type = Column(String(128), nullable=False)
    region = Column(String(64), nullable=True)
    severity = Column(Integer, nullable=False)        # 1-5
    exposure = Column(Integer, nullable=False)        # 1-5
    data_sensitivity = Column(Integer, nullable=False)  # 1-5
    risk_score = Column(Integer, nullable=False)      # 1-125
    band = Column(String(16), nullable=False)         # critical/high/medium/low
    evidence_json = Column(Text, nullable=True)
    cis_control = Column(String(32), nullable=True)
    remediation = Column(Text, nullable=True)
    cli_fix = Column(Text, nullable=True)
    status = Column(SAEnum(FindingStatus), default=FindingStatus.open, nullable=False)
    note = Column(Text, nullable=True)
    first_seen_scan_id = Column(Integer, nullable=True)
    diff_state = Column(SAEnum(FindingDiffState), default=FindingDiffState.new, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="findings")
    account = relationship("CloudAccount", back_populates="findings")


# ─── Resource Overrides ───────────────────────────────────────────────────────
class ResourceOverride(Base):
    __tablename__ = "resource_overrides"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("cloud_accounts.id"), nullable=False)
    resource_id = Column(String(512), nullable=False)
    data_sensitivity = Column(Integer, nullable=False)

    account = relationship("CloudAccount", back_populates="overrides")


# ─── Events ──────────────────────────────────────────────────────────────────
class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("cloud_accounts.id"), nullable=False)
    event_time = Column(DateTime, nullable=False)
    event_name = Column(String(256), nullable=False)
    event_source = Column(String(256), nullable=True)
    username = Column(String(256), nullable=True)
    user_arn = Column(String(512), nullable=True)
    source_ip = Column(String(64), nullable=True)
    region = Column(String(64), nullable=True)
    raw_json = Column(Text, nullable=True)

    account = relationship("CloudAccount", back_populates="events")
    alerts = relationship("Alert", back_populates="event")


# ─── Alerts ──────────────────────────────────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("cloud_accounts.id"), nullable=False)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=True)
    rule_id = Column(String(32), nullable=False)
    title = Column(String(512), nullable=False)
    severity = Column(SAEnum(AlertSeverity), nullable=False)
    status = Column(SAEnum(AlertStatus), default=AlertStatus.new, nullable=False)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    account = relationship("CloudAccount", back_populates="alerts")
    event = relationship("Event", back_populates="alerts")


# ─── IaC Scans ───────────────────────────────────────────────────────────────
class IacScan(Base):
    __tablename__ = "iac_scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    verdict = Column(String(8), nullable=True)  # PASS / FAIL
    summary_json = Column(Text, nullable=True)

    user = relationship("User", back_populates="iac_scans")
    findings = relationship("IacFinding", back_populates="iac_scan")


class IacFinding(Base):
    __tablename__ = "iac_findings"

    id = Column(Integer, primary_key=True, index=True)
    iac_scan_id = Column(Integer, ForeignKey("iac_scans.id"), nullable=False)
    check_id = Column(String(64), nullable=True)
    check_name = Column(String(512), nullable=True)
    file_path = Column(String(512), nullable=True)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    resource = Column(String(512), nullable=True)
    severity = Column(Integer, default=3)
    exposure = Column(Integer, default=3)
    data_sensitivity = Column(Integer, default=3)
    risk_score = Column(Integer, default=9)
    guideline = Column(Text, nullable=True)

    iac_scan = relationship("IacScan", back_populates="findings")


# ─── Settings ────────────────────────────────────────────────────────────────
class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(128), primary_key=True)
    value_json = Column(Text, nullable=False)


# ─── Audit Log ───────────────────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(128), nullable=False)
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="audit_logs")
