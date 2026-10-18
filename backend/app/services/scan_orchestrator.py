"""Scan orchestrator – runs all checks and saves findings to DB."""
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import AsyncSessionLocal
from app.models import (
    CloudAccount, Scan, Finding, ScanStatus, FindingStatus,
    FindingDiffState, ResourceOverride
)
from app.checks import ALL_CHECKS
from app.services.risk_engine import (
    calculate_risk_score, get_band, infer_data_sensitivity, calculate_account_risk_score
)
from app.services.ws_hub import ws_hub

logger = logging.getLogger(__name__)

# Steps in a scan
SCAN_STEPS = ["IAM", "Storage", "Network", "Logging", "Encryption", "Backup", "Scoring"]
CATEGORY_STEP_MAP = {
    "IAM": "IAM",
    "Storage": "Storage",
    "Network": "Network",
    "Logging": "Logging",
    "Encryption": "Encryption",
    "Backup": "Backup",
}


async def _broadcast_progress(scan_id: int, step: str, percent: int):
    await ws_hub.broadcast("scan.progress", {"scan_id": scan_id, "step": step, "percent": percent})


async def _broadcast_finding(scan_id: int, finding_data: dict):
    await ws_hub.broadcast("finding.new", {"scan_id": scan_id, "finding": finding_data})


async def run_demo_scan(scan_id: int, account_id: int):
    """Run scan against the built-in demo dataset."""
    import importlib.resources
    import pathlib

    data_path = pathlib.Path(__file__).parent.parent / "demo" / "data.json"
    with open(data_path) as f:
        demo_data = json.load(f)

    await _run_scan_with_data(scan_id, account_id, demo_data)


async def run_real_scan(scan_id: int, account_id: int, credentials: dict, region: str):
    """Run scan against a real AWS account using boto3."""
    try:
        from app.collectors.aws_collector import collect_all
        data = await asyncio.get_event_loop().run_in_executor(
            None, collect_all, credentials, region
        )
        await _run_scan_with_data(scan_id, account_id, data)
    except Exception as e:
        logger.error(f"Real scan failed: {e}")
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(Scan).where(Scan.id == scan_id).values(
                    status=ScanStatus.failed,
                    finished_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()
        await ws_hub.broadcast("scan.failed", {"scan_id": scan_id, "error": str(e)})


async def _run_scan_with_data(scan_id: int, account_id: int, data: dict):
    """Core scan logic – evaluate all checks and persist findings."""
    try:
        total_findings = 0
        all_findings: List[Finding] = []

        # Get overrides for data sensitivity
        async with AsyncSessionLocal() as db:
            overrides_result = await db.execute(
                select(ResourceOverride).where(ResourceOverride.account_id == account_id)
            )
            overrides = {o.resource_id: o.data_sensitivity for o in overrides_result.scalars().all()}

            # Get previous scan findings for diff
            prev_scan_result = await db.execute(
                select(Scan).where(
                    Scan.account_id == account_id,
                    Scan.id != scan_id,
                    Scan.status == ScanStatus.completed,
                ).order_by(Scan.id.desc()).limit(1)
            )
            prev_scan = prev_scan_result.scalar_one_or_none()
            prev_finding_keys = set()
            if prev_scan:
                prev_findings_result = await db.execute(
                    select(Finding.check_id, Finding.resource_id).where(Finding.scan_id == prev_scan.id)
                )
                prev_finding_keys = {(r.check_id, r.resource_id) for r in prev_findings_result}

        # Run checks by step
        steps = list(SCAN_STEPS)
        for step_idx, step_name in enumerate(steps[:-1]):  # Skip "Scoring"
            percent = int((step_idx / len(steps)) * 80)
            await _broadcast_progress(scan_id, step_name, percent)
            await asyncio.sleep(0.3)  # Small delay for UI visibility

            for check in ALL_CHECKS:
                if CATEGORY_STEP_MAP.get(check.category) != step_name:
                    continue
                try:
                    results = check.evaluate(data)
                    for result in results:
                        # Determine data sensitivity
                        ds = overrides.get(result.resource_id, None)
                        if ds is None:
                            ds = infer_data_sensitivity(
                                result.resource_id,
                                tags=result.tags if hasattr(result, 'tags') else {},
                                default=result.data_sensitivity_hint,
                            )

                        risk_score = calculate_risk_score(result.severity, result.exposure, ds)
                        band = get_band(risk_score)

                        # Determine diff state
                        key = (result.check_id, result.resource_id)
                        diff_state = FindingDiffState.new if key not in prev_finding_keys else FindingDiffState.existing

                        finding = Finding(
                            scan_id=scan_id,
                            account_id=account_id,
                            check_id=result.check_id,
                            title=result.title,
                            category=result.category,
                            resource_id=result.resource_id,
                            resource_type=result.resource_type,
                            region=result.region,
                            severity=result.severity,
                            exposure=result.exposure,
                            data_sensitivity=ds,
                            risk_score=risk_score,
                            band=band,
                            evidence_json=json.dumps(result.evidence),
                            cis_control=result.cis_control,
                            remediation=result.remediation,
                            cli_fix=result.cli_fix,
                            status=FindingStatus.open,
                            first_seen_scan_id=scan_id if diff_state == FindingDiffState.new else None,
                            diff_state=diff_state,
                        )

                        async with AsyncSessionLocal() as db:
                            db.add(finding)
                            await db.commit()
                            await db.refresh(finding)

                        all_findings.append(finding)
                        total_findings += 1

                        # Broadcast new finding
                        await _broadcast_finding(scan_id, {
                            "id": finding.id,
                            "check_id": finding.check_id,
                            "title": finding.title,
                            "category": finding.category,
                            "resource_id": finding.resource_id,
                            "severity": finding.severity,
                            "risk_score": finding.risk_score,
                            "band": finding.band,
                            "diff_state": finding.diff_state.value if finding.diff_state else "new",
                        })
                        await asyncio.sleep(0.1)
                except Exception as e:
                    logger.warning(f"Check {check.check_id} failed: {e}")

        # Scoring step
        await _broadcast_progress(scan_id, "Scoring", 85)
        await asyncio.sleep(0.3)

        # Calculate account risk score
        total_resources = _count_resources(data)
        open_findings = [f for f in all_findings if f.status == FindingStatus.open]
        account_risk = calculate_account_risk_score(open_findings, total_resources)

        # Build summary
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_category = {}
        for f in all_findings:
            by_severity[f.band] = by_severity.get(f.band, 0) + 1
            by_category[f.category] = by_category.get(f.category, 0) + 1

        summary = {
            "by_severity": by_severity,
            "by_category": by_category,
            "total_resources": total_resources,
        }

        # Complete scan
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(Scan).where(Scan.id == scan_id).values(
                    status=ScanStatus.completed,
                    finished_at=datetime.now(timezone.utc),
                    total_resources=total_resources,
                    total_findings=total_findings,
                    account_risk_score=account_risk,
                    summary_json=json.dumps(summary),
                )
            )
            # Update account last scan time
            await db.execute(
                update(CloudAccount).where(CloudAccount.id == account_id).values(
                    last_scan_at=datetime.now(timezone.utc)
                )
            )
            await db.commit()

        await _broadcast_progress(scan_id, "Completed", 100)
        await ws_hub.broadcast("scan.completed", {
            "scan_id": scan_id,
            "total_findings": total_findings,
            "account_risk_score": account_risk,
            "summary": summary,
        })

        logger.info(f"Scan {scan_id} completed: {total_findings} findings, risk={account_risk}")

    except Exception as e:
        logger.error(f"Scan {scan_id} crashed: {e}", exc_info=True)
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(Scan).where(Scan.id == scan_id).values(
                    status=ScanStatus.failed,
                    finished_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()
        await ws_hub.broadcast("scan.failed", {"scan_id": scan_id, "error": str(e)})


def _count_resources(data: dict) -> int:
    count = 0
    count += len(data.get("s3_buckets", []))
    count += len(data.get("iam", {}).get("users", []))
    count += len(data.get("security_groups", []))
    count += len(data.get("cloudtrail_trails", []))
    count += len(data.get("ebs_volumes", []))
    count += len(data.get("rds_instances", []))
    count += len(data.get("kms_keys", []))
    count += 2  # root account + account-level settings
    return max(count, 1)
