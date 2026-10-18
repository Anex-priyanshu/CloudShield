"""Events and Alerts routers."""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.db import get_db
from app.models import Event, Alert, AlertStatus, User
from app.schemas import EventOut, AlertOut, AlertUpdate
from app.auth import get_current_user

events_router = APIRouter(prefix="/events", tags=["events"])
alerts_router = APIRouter(prefix="/alerts", tags=["alerts"])


@events_router.get("", response_model=List[EventOut])
async def list_events(
    account_id: Optional[int] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = select(Event).order_by(Event.event_time.desc()).limit(limit)
    if account_id:
        q = q.where(Event.account_id == account_id)
    result = await db.execute(q)
    return result.scalars().all()


@alerts_router.get("", response_model=List[AlertOut])
async def list_alerts(
    account_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[AlertStatus] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    filters = []
    if account_id:
        filters.append(Alert.account_id == account_id)
    if severity:
        filters.append(Alert.severity == severity)
    if status:
        filters.append(Alert.status == status)

    q = select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    if filters:
        q = q.where(and_(*filters))
    result = await db.execute(q)
    return result.scalars().all()


@alerts_router.patch("/{alert_id}", response_model=AlertOut)
async def update_alert(
    alert_id: int,
    body: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if body.status is not None:
        alert.status = body.status
    if body.note is not None:
        alert.note = body.note
    await db.commit()
    await db.refresh(alert)
    return alert
