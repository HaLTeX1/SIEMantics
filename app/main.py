import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.auth import ensure_initial_admin
from app.config import settings
from app.db import init_db
from app.iris_sync import case_syncer
from app.pipeline import alert_queue
from app.routers import alerts, auth, cases, metrics, suppressions, users

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("siemantics")

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await ensure_initial_admin()
    if not settings.wazuh_webhook_token:
        logger.warning(
            "WAZUH_WEBHOOK_TOKEN is not set: POST /api/v1/alerts accepts alerts from anyone - "
            "set it (and the same value as <api_key> in the Wazuh integration) before connecting Wazuh"
        )
    await alert_queue.start(settings.triage_workers)
    case_syncer.start(settings.iris_sync_interval_seconds)
    try:
        yield
    finally:
        await case_syncer.stop()
        await alert_queue.stop()


app = FastAPI(title="SIEMantics", version="0.1.0", lifespan=lifespan)
app.include_router(alerts.router)
app.include_router(metrics.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(cases.router)
app.include_router(suppressions.router)
app.mount("/ui", StaticFiles(directory=STATIC_DIR, html=True), name="ui")


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/ui/")


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "queued_alerts": alert_queue.size(), "ignored_alerts": alerts.ignored_counter["count"]}
