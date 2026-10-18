"""Settings router – manage risk weights, thresholds, enabled checks, and user preferences."""
import json
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.db import get_db
from app.models import User, Setting, Finding, UserRole
from app.auth import get_current_user, require_admin, hash_password, verify_password
from app.services.risk_engine import compute_risk_score, classify_band
from app.checks import ALL_CHECKS
from app.detections import ALL_RULES

router = APIRouter(prefix="/settings", tags=["Settings"])


@router.get("")
async def get_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve all platform settings."""
    result = await db.execute(select(Setting))
    settings_rows = result.scalars().all()
    settings_dict = {}
    for s in settings_rows:
        try:
            settings_dict[s.key] = json.loads(s.value_json)
        except Exception:
            settings_dict[s.key] = s.value_json

    # Provide lists of all checks and rules for toggle UI
    all_checks_meta = [
        {"id": c.id, "title": c.title, "category": c.category, "severity": c.severity}
        for c in ALL_CHECKS
    ]
    all_rules_meta = [
        {"id": r["id"], "title": r["title"], "severity": r["severity"]}
        for r in ALL_RULES
    ]

    return {
        "settings": settings_dict,
        "available_checks": all_checks_meta,
        "available_rules": all_rules_meta,
    }


@router.put("")
async def update_settings(
    payload: dict = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Update settings keys (Admin only)."""
    for key, value in payload.items():
        result = await db.execute(select(Setting).where(Setting.key == key))
        existing = result.scalar_one_or_none()
        val_str = json.dumps(value) if not isinstance(value, str) else value
        if existing:
            existing.value_json = val_str
        else:
            db.add(Setting(key=key, value_json=val_str))

    await db.commit()
    return {"status": "ok", "message": "Settings updated successfully"}


@router.post("/recalculate")
async def recalculate_risk_scores(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Recalculate risk scores for all open findings based on active band settings."""
    result = await db.execute(select(Setting).where(Setting.key == "risk_bands"))
    row = result.scalar_one_or_none()
    custom_bands = json.loads(row.value_json) if row else None

    findings_res = await db.execute(select(Finding))
    findings = findings_res.scalars().all()

    count = 0
    for f in findings:
        score, band = compute_risk_score(
            f.severity, f.exposure, f.data_sensitivity, custom_bands
        )
        f.risk_score = score
        f.band = band
        count += 1

    await db.commit()
    return {"status": "ok", "recalculated_findings": count}


@router.post("/change-password")
async def change_password(
    current_password: str = Body(..., embed=True),
    new_password: str = Body(..., embed=True),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Change current authenticated user's password."""
    if not verify_password(current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters long")

    current_user.password_hash = hash_password(new_password)
    await db.commit()
    return {"status": "ok", "message": "Password changed successfully"}
