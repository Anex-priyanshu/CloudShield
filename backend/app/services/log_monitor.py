"""Log monitor service – polls real AWS CloudTrail and detects security threats in real-time."""
import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.db import AsyncSessionLocal
from app.models import CloudAccount, Event, Alert, AlertSeverity, AlertStatus
from app.detections.rules import evaluate_event
from app.services.ws_hub import ws_hub
from app.config import settings

logger = logging.getLogger(__name__)


async def process_cloudtrail_event(event_raw: dict, account_id: int, db) -> Optional[Alert]:
    """Process a single CloudTrail event, store it, check rules, create alerts."""
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
        username=event_raw.get("username") or identity.get("userName") or identity.get("type", "Unknown"),
        user_arn=identity.get("arn", ""),
        source_ip=event_raw.get("sourceIPAddress", "unknown"),
        region=event_raw.get("awsRegion", "us-east-1"),
        raw_json=json.dumps(event_raw),
    )
    db.add(event)
    await db.flush()

    # Broadcast event over WebSocket
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
        severity_map = {
            "critical": AlertSeverity.critical,
            "high": AlertSeverity.high,
            "medium": AlertSeverity.medium,
            "low": AlertSeverity.low,
        }
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

        # Broadcast alert over WebSocket
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
        logger.info(f"Real CloudTrail Alert: [{rule.severity.upper()}] {rule.get_title(event_raw)}")

    return created_alert


_active_monitors: dict = {}


async def real_cloudtrail_poll_loop(account_id: int):
    """Continuously poll real AWS CloudTrail for new audit events."""
    from app.auth import decrypt_credentials
    from app.collectors.aws_collector import _make_session

    logger.info(f"CloudTrail monitoring poller started for real account {account_id}")
    last_event_time = datetime.now(timezone.utc) - timedelta(minutes=15)

    while True:
        try:
            async with AsyncSessionLocal() as db:
                from sqlalchemy import select
                acc_res = await db.execute(select(CloudAccount).where(CloudAccount.id == account_id))
                account = acc_res.scalar_one_or_none()

                if not account or not account.credentials_encrypted:
                    logger.info(f"No credentials found for account {account_id}. Stopping poller.")
                    break

                creds = decrypt_credentials(account.credentials_encrypted)
                region = account.region or "us-east-1"

                def _fetch():
                    try:
                        session = _make_session(creds, region)
                        ct = session.client("cloudtrail")
                        resp = ct.lookup_events(
                            StartTime=last_event_time,
                            MaxResults=50,
                        )
                        return resp.get("Events", [])
                    except Exception as err:
                        logger.warning(f"CloudTrail lookup_events error: {err}")
                        return []

                raw_events = await asyncio.get_event_loop().run_in_executor(None, _fetch)

                for ev in sorted(raw_events, key=lambda x: x.get("EventTime", datetime.now(timezone.utc))):
                    ev_time = ev.get("EventTime")
                    if isinstance(ev_time, datetime) and ev_time > last_event_time:
                        last_event_time = ev_time

                    cloudtrail_json = ev.get("CloudTrailEvent", "{}")
                    try:
                        parsed = json.loads(cloudtrail_json) if isinstance(cloudtrail_json, str) else cloudtrail_json
                    except Exception:
                        parsed = {}

                    merged = {
                        "eventName": ev.get("EventName") or parsed.get("eventName", ""),
                        "eventTime": ev_time.isoformat() if isinstance(ev_time, datetime) else str(ev_time),
                        "eventSource": ev.get("EventSource") or parsed.get("eventSource", ""),
                        "username": ev.get("Username") or parsed.get("userIdentity", {}).get("userName", ""),
                        "sourceIPAddress": parsed.get("sourceIPAddress", "unknown"),
                        "awsRegion": parsed.get("awsRegion", region),
                        "userIdentity": parsed.get("userIdentity", {}),
                        "requestParameters": parsed.get("requestParameters", {}),
                        "responseElements": parsed.get("responseElements", {}),
                        "additionalEventData": parsed.get("additionalEventData", {}),
                    }

                    await process_cloudtrail_event(merged, account_id, db)

                await db.commit()

            poll_sec = max(15, getattr(settings, 'log_poll_interval_seconds', 30))
            await asyncio.sleep(poll_sec)
        except asyncio.CancelledError:
            logger.info(f"CloudTrail monitor cancelled for account {account_id}")
            break
        except Exception as e:
            logger.error(f"CloudTrail monitoring loop error for account {account_id}: {e}")
            await asyncio.sleep(30)


async def start_account_monitor(account_id: int):
    """Start the real CloudTrail poller for an account."""
    if account_id not in _active_monitors:
        task = asyncio.create_task(real_cloudtrail_poll_loop(account_id))
        _active_monitors[account_id] = task
        logger.info(f"Initiated real CloudTrail monitor task for account {account_id}")


async def stop_account_monitor(account_id: int):
    """Stop the CloudTrail poller for an account."""
    if account_id in _active_monitors:
        _active_monitors[account_id].cancel()
        del _active_monitors[account_id]
        logger.info(f"Stopped CloudTrail monitor for account {account_id}")


async def start_all_monitors():
    """Start real CloudTrail monitors for all connected AWS accounts on startup."""
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(
            select(CloudAccount).where(CloudAccount.credentials_encrypted.isnot(None))
        )
        accounts = result.scalars().all()
        for account in accounts:
            await start_account_monitor(account.id)
