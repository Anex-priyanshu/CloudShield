"""Log monitor service – polls CloudTrail and drives the demo event generator."""
import asyncio
import json
import logging
import random
from datetime import datetime, timezone
from typing import Optional

from app.db import AsyncSessionLocal
from app.models import CloudAccount, AccountProvider, Event, Alert, AlertSeverity, AlertStatus
from app.detections.rules import evaluate_event
from app.services.ws_hub import ws_hub
from app.config import settings

logger = logging.getLogger(__name__)


async def process_cloudtrail_event(event_raw: dict, account_id: int, db) -> Optional[Alert]:
    """Process a single CloudTrail event, store it, check rules, create alerts."""
    # Parse event
    event_time_str = event_raw.get("eventTime", datetime.now(timezone.utc).isoformat())
    try:
        if isinstance(event_time_str, str):
            event_time = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
        else:
            event_time = event_time_str
    except Exception:
        event_time = datetime.now(timezone.utc)

    identity = event_raw.get("userIdentity", {})

    event = Event(
        account_id=account_id,
        event_time=event_time,
        event_name=event_raw.get("eventName", ""),
        event_source=event_raw.get("eventSource", ""),
        username=identity.get("userName") or identity.get("type", ""),
        user_arn=identity.get("arn", ""),
        source_ip=event_raw.get("sourceIPAddress", ""),
        region=event_raw.get("awsRegion", "us-east-1"),
        raw_json=json.dumps(event_raw),
    )
    db.add(event)
    await db.flush()

    # Broadcast event
    await ws_hub.broadcast("event.new", {
        "account_id": account_id,
        "event_id": event.id,
        "event_name": event.event_name,
        "username": event.username,
        "source_ip": event.source_ip,
        "region": event.region,
        "event_time": event.event_time.isoformat(),
    })

    # Evaluate detection rules
    matched_rules = evaluate_event(event_raw)
    created_alert = None

    for rule in matched_rules:
        severity_map = {"critical": AlertSeverity.critical, "high": AlertSeverity.high,
                        "medium": AlertSeverity.medium, "low": AlertSeverity.low}
        alert = Alert(
            account_id=account_id,
            event_id=event.id,
            rule_id=rule.rule_id,
            title=rule.get_title(event_raw),
            severity=severity_map.get(rule.severity, AlertSeverity.medium),
            status=AlertStatus.new,
        )
        db.add(alert)
        await db.flush()

        # Broadcast alert
        await ws_hub.broadcast("alert.new", {
            "id": alert.id,
            "account_id": account_id,
            "rule_id": rule.rule_id,
            "title": alert.title,
            "severity": rule.severity,
            "status": "new",
            "created_at": alert.created_at.isoformat() if alert.created_at else datetime.now(timezone.utc).isoformat(),
        })
        created_alert = alert
        logger.info(f"Alert created: [{rule.severity.upper()}] {rule.get_title(event_raw)}")

    return created_alert


async def demo_event_loop(account_id: int):
    """Generate and process fake CloudTrail events for demo accounts."""
    from app.demo.event_generator import generate_demo_event
    logger.info(f"Demo event loop started for account {account_id}")

    while True:
        try:
            interval = random.uniform(settings.demo_event_interval_min, settings.demo_event_interval_max)
            await asyncio.sleep(interval)

            event_raw = generate_demo_event()
            async with AsyncSessionLocal() as db:
                await process_cloudtrail_event(event_raw, account_id, db)
                await db.commit()
        except asyncio.CancelledError:
            logger.info(f"Demo event loop cancelled for account {account_id}")
            break
        except Exception as e:
            logger.error(f"Demo event loop error: {e}")
            await asyncio.sleep(5)


_demo_tasks: dict = {}


async def start_demo_monitor(account_id: int):
    """Start the demo event generator for an account."""
    if account_id not in _demo_tasks:
        task = asyncio.create_task(demo_event_loop(account_id))
        _demo_tasks[account_id] = task
        logger.info(f"Started demo monitor for account {account_id}")


async def start_all_demo_monitors():
    """Start demo monitors for all demo accounts at startup."""
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(
            select(CloudAccount).where(CloudAccount.is_demo == True)
        )
        demo_accounts = result.scalars().all()
        for account in demo_accounts:
            await start_demo_monitor(account.id)
