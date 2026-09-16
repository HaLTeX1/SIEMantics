import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.db import init_db
from app.routers import alerts, metrics

logging.basicConfig(level=logging.INFO)

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="SIEMantics", version="0.1.0", lifespan=lifespan)
app.include_router(alerts.router)
app.include_router(metrics.router)
app.mount("/ui", StaticFiles(directory=STATIC_DIR, html=True), name="ui")


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/ui/")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
