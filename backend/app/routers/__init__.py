from app.routers.auth import router as auth_router
from app.routers.accounts import router as accounts_router
from app.routers.scans import router as scans_router
from app.routers.findings import router as findings_router
from app.routers.dashboard import router as dashboard_router
from app.routers.monitor import events_router, alerts_router
from app.routers.iac import router as iac_router
from app.routers.reports import router as reports_router
from app.routers.settings import router as settings_router

__all__ = [
    "auth_router",
    "accounts_router",
    "scans_router",
    "findings_router",
    "dashboard_router",
    "events_router",
    "alerts_router",
    "iac_router",
    "reports_router",
    "settings_router",
]
