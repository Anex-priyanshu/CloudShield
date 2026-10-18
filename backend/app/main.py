"""CloudShield FastAPI application – main entry point."""
import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings as config_settings
from app.db import init_db, AsyncSessionLocal
from app.models import User, UserRole, Setting
from app.auth import hash_password, get_ws_user
from app.services.ws_hub import ws_hub
from app.services.log_monitor import start_all_monitors
from app.routers import auth, accounts, scans, findings, dashboard, monitor, iac, reports, settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def seed_admin():
    """Create the initial admin user if it doesn't exist."""
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.email == config_settings.admin_email))
        existing = result.scalar_one_or_none()
        if not existing:
            admin = User(
                email=config_settings.admin_email,
                password_hash=hash_password(config_settings.admin_password),
                role=UserRole.admin,
            )
            db.add(admin)
            await db.commit()
            logger.info(f"Seeded admin user: {config_settings.admin_email}")


async def seed_default_settings():
    """Seed default settings if not present."""
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        defaults = {
            "risk_weights": {"severity": 1, "exposure": 1, "data_sensitivity": 1},
            "risk_bands": {"critical_min": 91, "high_min": 51, "medium_min": 21},
            "default_data_sensitivity": 3,
            "log_poll_interval": 30,
            "enabled_checks": [],  # empty = all enabled
            "enabled_rules": [],   # empty = all enabled
        }
        for key, value in defaults.items():
            result = await db.execute(select(Setting).where(Setting.key == key))
            if not result.scalar_one_or_none():
                db.add(Setting(key=key, value_json=json.dumps(value)))
        await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("CloudShield starting up...")
    await init_db()
    await seed_admin()
    await seed_default_settings()
    await start_all_monitors()
    logger.info("CloudShield ready!")
    yield
    # Shutdown
    logger.info("CloudShield shutting down...")


app = FastAPI(
    title="CloudShield API",
    description="Cloud Security Posture Assessment Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[config_settings.frontend_url, "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_origin_regex=r"^https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
API_PREFIX = "/api/v1"
app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(accounts.router, prefix=API_PREFIX)
app.include_router(scans.router, prefix=API_PREFIX)
app.include_router(findings.router, prefix=API_PREFIX)
app.include_router(dashboard.router, prefix=API_PREFIX)
app.include_router(monitor.events_router, prefix=API_PREFIX)
app.include_router(monitor.alerts_router, prefix=API_PREFIX)
app.include_router(iac.router, prefix=API_PREFIX)
app.include_router(reports.router, prefix=API_PREFIX)
app.include_router(settings.router, prefix=API_PREFIX)


@app.get(f"{API_PREFIX}/health")
async def health():
    return {"status": "ok", "service": "CloudShield API", "version": "1.0.0"}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(...)):
    async with AsyncSessionLocal() as db:
        user = await get_ws_user(token, db)

    if not user:
        await websocket.close(code=1008)
        return

    await ws_hub.connect(websocket)
    try:
        # Send ping immediately
        await ws_hub.send_to(websocket, "ws.ping", {"message": "Connected to CloudShield"})
        while True:
            # Keep connection alive
            data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
    except asyncio.TimeoutError:
        # Send ping to keep alive
        try:
            await ws_hub.send_to(websocket, "ws.ping", {})
        except Exception:
            pass
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
    finally:
        await ws_hub.disconnect(websocket)
