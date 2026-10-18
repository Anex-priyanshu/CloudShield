"""IaC Scanner API router – upload Terraform/CloudFormation files, run scans, gate evaluation."""
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.db import get_db
from app.models import User, IacScan, IacFinding
from app.auth import get_current_user
from app.services.iac_scanner import (
    run_iac_analysis, SAMPLE_INSECURE_TF, SAMPLE_SECURE_TF
)

router = APIRouter(prefix="/iac", tags=["IaC Scanner"])


@router.post("/sample")
async def scan_sample(
    sample_type: str = Form("insecure"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Scan built-in insecure or secure Terraform sample for instant one-click demo."""
    content = SAMPLE_INSECURE_TF if sample_type == "insecure" else SAMPLE_SECURE_TF
    filename = "sample_insecure.tf" if sample_type == "insecure" else "sample_secure.tf"

    result = run_iac_analysis([(filename, content)])
    
    # Save to DB
    iac_scan = IacScan(
        user_id=current_user.id,
        verdict=result["verdict"],
        summary_json=json.dumps(result["summary"]),
    )
    db.add(iac_scan)
    await db.flush()

    for item in result["findings"]:
        finding = IacFinding(
            iac_scan_id=iac_scan.id,
            check_id=item["check_id"],
            check_name=item["check_name"],
            file_path=item["file_path"],
            line_start=item["line_start"],
            line_end=item["line_end"],
            resource=item["resource"],
            severity=item["severity"],
            exposure=item["exposure"],
            data_sensitivity=item["data_sensitivity"],
            risk_score=item["risk_score"],
            guideline=item["guideline"],
        )
        db.add(finding)

    await db.commit()
    await db.refresh(iac_scan)

    return {
        "scan_id": iac_scan.id,
        "sample_type": sample_type,
        "verdict": result["verdict"],
        "summary": result["summary"],
        "findings": result["findings"],
        "raw_code": content,
    }


@router.post("/scan")
async def scan_files(
    files: List[UploadFile] = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Upload and scan one or more .tf, .json, .yaml files (max 5MB each)."""
    ALLOWED_EXTENSIONS = {".tf", ".json", ".yaml", ".yml"}
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

    parsed_files = []
    first_file_content = ""

    for file in files:
        # Check extension
        ext = "." + file.filename.split(".")[-1].lower() if "." in file.filename else ""
        if ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type '{ext}'. Allowed: .tf, .json, .yaml, .yml"
            )

        content_bytes = await file.read()
        if len(content_bytes) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"File '{file.filename}' exceeds maximum allowed size of 5MB."
            )

        try:
            content_str = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            content_str = content_bytes.decode("latin-1")

        parsed_files.append((file.filename, content_str))
        if not first_file_content:
            first_file_content = content_str

    result = run_iac_analysis(parsed_files)

    iac_scan = IacScan(
        user_id=current_user.id,
        verdict=result["verdict"],
        summary_json=json.dumps(result["summary"]),
    )
    db.add(iac_scan)
    await db.flush()

    for item in result["findings"]:
        finding = IacFinding(
            iac_scan_id=iac_scan.id,
            check_id=item["check_id"],
            check_name=item["check_name"],
            file_path=item["file_path"],
            line_start=item["line_start"],
            line_end=item["line_end"],
            resource=item["resource"],
            severity=item["severity"],
            exposure=item["exposure"],
            data_sensitivity=item["data_sensitivity"],
            risk_score=item["risk_score"],
            guideline=item["guideline"],
        )
        db.add(finding)

    await db.commit()
    await db.refresh(iac_scan)

    return {
        "scan_id": iac_scan.id,
        "verdict": result["verdict"],
        "summary": result["summary"],
        "findings": result["findings"],
        "raw_code": first_file_content,
    }


@router.get("/scans")
async def list_iac_scans(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List past IaC scans with verdict and timestamp."""
    result = await db.execute(
        select(IacScan).order_by(desc(IacScan.created_at)).limit(20)
    )
    scans = result.scalars().all()
    return [
        {
            "id": s.id,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "verdict": s.verdict,
            "summary": json.loads(s.summary_json) if s.summary_json else {},
        }
        for s in scans
    ]
