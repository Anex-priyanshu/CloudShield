"""Scans router."""
import asyncio
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.db import get_db
from app.models import Scan, CloudAccount, ScanStatus, Finding, FindingStatus, FindingDiffState, User
from app.schemas import ScanOut, ScanStart
from app.auth import get_current_user, get_current_admin, decrypt_credentials

router = APIRouter(prefix="/scans", tags=["scans"])


async def _start_scan_task(scan_id: int, account_id: int, is_demo: bool, credentials: Optional[dict], region: str):
    from app.services.scan_orchestrator import run_demo_scan, run_real_scan
    if is_demo:
        await run_demo_scan(scan_id, account_id)
    else:
        await run_real_scan(scan_id, account_id, credentials or {}, region)


@router.post("", response_model=ScanOut)
async def start_scan(
    body: ScanStart,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(select(CloudAccount).where(CloudAccount.id == body.account_id))
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    scan = Scan(account_id=body.account_id, status=ScanStatus.running)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    creds = None
    if not account.is_demo and account.credentials_encrypted:
        creds = decrypt_credentials(account.credentials_encrypted)

    asyncio.create_task(
        _start_scan_task(scan.id, account.id, account.is_demo, creds, account.region)
    )

    return scan


@router.get("", response_model=List[ScanOut])
async def list_scans(
    account_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = select(Scan).order_by(Scan.started_at.desc()).limit(50)
    if account_id:
        q = q.where(Scan.account_id == account_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/cancel", response_model=ScanOut)
async def cancel_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status == ScanStatus.running:
        scan.status = ScanStatus.cancelled
        await db.commit()
        await db.refresh(scan)
    return scan


@router.get("/{scan_id}/compare", response_model=dict)
async def compare_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    prev_result = await db.execute(
        select(Scan).where(
            Scan.account_id == scan.account_id,
            Scan.id < scan_id,
            Scan.status == ScanStatus.completed,
        ).order_by(Scan.id.desc()).limit(1)
    )
    prev_scan = prev_result.scalar_one_or_none()

    current_findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    current_findings = current_findings_result.scalars().all()

    new_count = sum(1 for f in current_findings if f.diff_state == FindingDiffState.new)
    existing_count = sum(1 for f in current_findings if f.diff_state == FindingDiffState.existing)

    return {
        "current_scan_id": scan_id,
        "previous_scan_id": prev_scan.id if prev_scan else None,
        "new": new_count,
        "existing": existing_count,
        "fixed": 0,  # Would require checking prev findings not in current
    }
