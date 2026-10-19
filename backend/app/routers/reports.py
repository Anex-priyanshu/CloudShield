"""Reports API router – generate PDF, CSV, and JSON scan reports."""
import json
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.db import get_db
from app.models import User, Scan, Finding, CloudAccount, ScanStatus
from app.auth import get_current_user
from app.services.report_generator import generate_scan_pdf, generate_scan_csv

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("")
async def list_reports(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all completed scans that have reports available."""
    result = await db.execute(
        select(Scan, CloudAccount)
        .join(CloudAccount, Scan.account_id == CloudAccount.id)
        .where(Scan.status == ScanStatus.completed)
        .order_by(desc(Scan.started_at))
        .limit(30)
    )
    rows = result.all()
    reports = []
    for scan, account in rows:
        summary = json.loads(scan.summary_json) if scan.summary_json else {}
        reports.append({
            "scan_id": scan.id,
            "account_id": account.id,
            "account_name": account.name,
            "provider": account.provider.value if hasattr(account.provider, "value") else str(account.provider),
            "region": account.region,
            "is_demo": account.is_demo,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "total_resources": scan.total_resources,
            "total_findings": scan.total_findings,
            "account_risk_score": scan.account_risk_score,
            "summary": summary,
        })
    return reports


@router.get("/{scan_id}/pdf")
async def download_scan_pdf(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate and download a branded PDF report for a completed scan."""
    result = await db.execute(
        select(Scan, CloudAccount)
        .join(CloudAccount, Scan.account_id == CloudAccount.id)
        .where(Scan.id == scan_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan, account = row

    findings_res = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = findings_res.scalars().all()
    findings_dicts = [
        {
            "id": f.id,
            "check_id": f.check_id,
            "title": f.title,
            "category": f.category,
            "resource_id": f.resource_id,
            "resource_type": f.resource_type,
            "region": f.region,
            "severity": f.severity,
            "exposure": f.exposure,
            "data_sensitivity": f.data_sensitivity,
            "risk_score": f.risk_score,
            "band": f.band,
            "cis_control": f.cis_control,
            "remediation": f.remediation,
            "cli_fix": f.cli_fix,
            "status": f.status.value if hasattr(f.status, "value") else str(f.status),
        }
        for f in findings
    ]

    scan_data = {
        "id": scan.id,
        "account_risk_score": scan.account_risk_score,
        "total_resources": scan.total_resources,
        "total_findings": scan.total_findings,
        "started_at": scan.started_at.isoformat() if scan.started_at else "",
    }
    account_data = {
        "name": account.name,
        "provider": account.provider.value if hasattr(account.provider, "value") else str(account.provider),
        "region": account.region,
        "account_id": account.account_id or "550054567551",
    }

    pdf_bytes = generate_scan_pdf(scan_data, account_data, findings_dicts)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="CloudShield_Assessment_Scan_{scan_id}.pdf"'
        }
    )


@router.get("/{scan_id}/csv")
async def download_scan_csv(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download CSV export of scan findings."""
    findings_res = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = findings_res.scalars().all()
    findings_dicts = [
        {
            "id": f.id,
            "check_id": f.check_id,
            "title": f.title,
            "category": f.category,
            "resource_id": f.resource_id,
            "resource_type": f.resource_type,
            "region": f.region,
            "severity": f.severity,
            "exposure": f.exposure,
            "data_sensitivity": f.data_sensitivity,
            "risk_score": f.risk_score,
            "band": f.band,
            "cis_control": f.cis_control,
            "remediation": f.remediation,
            "cli_fix": f.cli_fix,
            "status": f.status.value if hasattr(f.status, "value") else str(f.status),
        }
        for f in findings
    ]

    csv_text = generate_scan_csv(findings_dicts)
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="CloudShield_Findings_Scan_{scan_id}.csv"'
        }
    )


@router.get("/{scan_id}/json")
async def download_scan_json(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download full JSON payload of scan and findings."""
    result = await db.execute(
        select(Scan, CloudAccount)
        .join(CloudAccount, Scan.account_id == CloudAccount.id)
        .where(Scan.id == scan_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan, account = row

    findings_res = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = findings_res.scalars().all()

    payload = {
        "scan": {
            "id": scan.id,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "account_risk_score": scan.account_risk_score,
            "total_resources": scan.total_resources,
            "total_findings": scan.total_findings,
            "summary": json.loads(scan.summary_json) if scan.summary_json else {},
        },
        "account": {
            "name": account.name,
            "provider": account.provider.value if hasattr(account.provider, "value") else str(account.provider),
            "region": account.region,
            "is_demo": account.is_demo,
        },
        "findings": [
            {
                "id": f.id,
                "check_id": f.check_id,
                "title": f.title,
                "category": f.category,
                "resource_id": f.resource_id,
                "resource_type": f.resource_type,
                "region": f.region,
                "severity": f.severity,
                "exposure": f.exposure,
                "data_sensitivity": f.data_sensitivity,
                "risk_score": f.risk_score,
                "band": f.band,
                "cis_control": f.cis_control,
                "remediation": f.remediation,
                "cli_fix": f.cli_fix,
                "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                "evidence": json.loads(f.evidence_json) if f.evidence_json else {},
            }
            for f in findings
        ]
    }
    return payload
