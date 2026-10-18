"""Dashboard router."""
import json
from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from app.db import get_db
from app.models import Finding, FindingStatus, Scan, ScanStatus, Alert, User
from app.schemas import DashboardSummary, FindingOut, AlertOut, ScanOut, TrendPoint
from app.auth import get_current_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
async def dashboard_summary(
    account_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    filters = [Finding.status == FindingStatus.open]
    if account_id:
        filters.append(Finding.account_id == account_id)

    # Counts by band
    findings_result = await db.execute(select(Finding).where(and_(*filters)))
    all_open = findings_result.scalars().all()

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_category = {}
    for f in all_open:
        counts[f.band] = counts.get(f.band, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1

    # Top 5 risks
    top5_result = await db.execute(
        select(Finding).where(and_(*filters)).order_by(Finding.risk_score.desc()).limit(5)
    )
    top5 = top5_result.scalars().all()

    # Recent alerts
    alert_filters = []
    if account_id:
        alert_filters.append(Alert.account_id == account_id)
    alerts_result = await db.execute(
        select(Alert).where(and_(*alert_filters) if alert_filters else True).order_by(Alert.created_at.desc()).limit(10)
    )
    recent_alerts = alerts_result.scalars().all()

    # Last scan
    scan_filters = []
    if account_id:
        scan_filters.append(Scan.account_id == account_id)
    last_scan_result = await db.execute(
        select(Scan).where(and_(*scan_filters) if scan_filters else True).order_by(Scan.started_at.desc()).limit(1)
    )
    last_scan = last_scan_result.scalar_one_or_none()

    # Account risk score
    account_risk = last_scan.account_risk_score if last_scan else 0.0

    # Compliance snapshot (% checks passed per category)
    all_findings_result = await db.execute(
        select(Finding).where(Finding.account_id == account_id) if account_id else select(Finding)
    )
    all_findings = all_findings_result.scalars().all()

    from app.checks import CHECK_CATEGORIES
    compliance_pct = {}
    for cat, checks in CHECK_CATEGORIES.items():
        total_checks = len(checks)
        if total_checks == 0:
            compliance_pct[cat] = 100.0
            continue
        failed_check_ids = {f.check_id for f in all_open if f.category == cat}
        failed = len(failed_check_ids)
        passed = total_checks - min(failed, total_checks)
        compliance_pct[cat] = round((passed / total_checks) * 100, 1)

    return {
        "account_risk_score": account_risk,
        "total_open": len(all_open),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "by_category": by_category,
        "compliance_pct": compliance_pct,
        "top5_risks": [FindingOut.model_validate(f) for f in top5],
        "recent_alerts": [AlertOut.model_validate(a) for a in recent_alerts],
        "last_scan": ScanOut.model_validate(last_scan) if last_scan else None,
    }


@router.get("/trend")
async def dashboard_trend(
    account_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    filters = [Scan.status == ScanStatus.completed]
    if account_id:
        filters.append(Scan.account_id == account_id)

    result = await db.execute(
        select(Scan).where(and_(*filters)).order_by(Scan.started_at.asc()).limit(10)
    )
    scans = result.scalars().all()

    return [
        TrendPoint(
            scan_id=s.id,
            started_at=s.started_at,
            account_risk_score=s.account_risk_score,
            total_findings=s.total_findings,
        )
        for s in scans
    ]
