"""Findings router with filtering, sorting, bulk actions, and CSV export."""
import csv
import io
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_

from app.db import get_db
from app.models import Finding, FindingStatus, User
from app.schemas import FindingOut, FindingUpdate, BulkStatusUpdate, PaginatedFindings
from app.auth import get_current_user, get_current_admin

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=PaginatedFindings)
async def list_findings(
    severity: Optional[int] = None,
    category: Optional[str] = None,
    status: Optional[FindingStatus] = None,
    account_id: Optional[int] = None,
    scan_id: Optional[int] = None,
    q: Optional[str] = None,
    sort: str = "risk_score",
    page: int = 1,
    page_size: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    filters = []
    if severity is not None:
        filters.append(Finding.severity == severity)
    if category:
        filters.append(Finding.category == category)
    if status:
        filters.append(Finding.status == status)
    if account_id:
        filters.append(Finding.account_id == account_id)
    if scan_id:
        filters.append(Finding.scan_id == scan_id)
    if q:
        filters.append(or_(
            Finding.title.ilike(f"%{q}%"),
            Finding.resource_id.ilike(f"%{q}%"),
        ))

    # Count
    count_q = select(func.count()).select_from(Finding)
    if filters:
        count_q = count_q.where(and_(*filters))
    total_result = await db.execute(count_q)
    total = total_result.scalar()

    # Sort
    sort_col = Finding.risk_score
    if sort == "severity":
        sort_col = Finding.severity
    elif sort == "created_at":
        sort_col = Finding.created_at

    # Fetch
    q_stmt = select(Finding)
    if filters:
        q_stmt = q_stmt.where(and_(*filters))
    q_stmt = q_stmt.order_by(sort_col.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q_stmt)
    items = result.scalars().all()

    return PaginatedFindings(total=total, page=page, page_size=page_size, items=items)


@router.get("/export/csv")
async def export_csv(
    account_id: Optional[int] = None,
    scan_id: Optional[int] = None,
    status: Optional[FindingStatus] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    filters = []
    if account_id:
        filters.append(Finding.account_id == account_id)
    if scan_id:
        filters.append(Finding.scan_id == scan_id)
    if status:
        filters.append(Finding.status == status)

    q = select(Finding)
    if filters:
        q = q.where(and_(*filters))
    q = q.order_by(Finding.risk_score.desc())
    result = await db.execute(q)
    findings = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Check ID", "Title", "Category", "Resource", "Severity", "Risk Score", "Band", "Status", "CIS Control", "Created At"])
    for f in findings:
        writer.writerow([f.id, f.check_id, f.title, f.category, f.resource_id, f.severity, f.risk_score, f.band, f.status.value, f.cis_control, f.created_at])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cloudshield_findings.csv"},
    )


@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingOut)
async def update_finding(
    finding_id: int,
    body: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if body.status is not None:
        finding.status = body.status
    if body.note is not None:
        finding.note = body.note
    if body.data_sensitivity is not None:
        from app.services.risk_engine import calculate_risk_score, get_band
        finding.data_sensitivity = body.data_sensitivity
        finding.risk_score = calculate_risk_score(finding.severity, finding.exposure, body.data_sensitivity)
        finding.band = get_band(finding.risk_score)

    await db.commit()
    await db.refresh(finding)
    return finding


@router.post("/bulk", response_model=dict)
async def bulk_update(
    body: BulkStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Finding).where(Finding.id.in_(body.finding_ids)))
    findings = result.scalars().all()
    for f in findings:
        f.status = body.status
        if body.note:
            f.note = body.note
    await db.commit()
    return {"updated": len(findings)}
