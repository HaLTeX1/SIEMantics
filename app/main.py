import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db import init_db
from app.routers import alerts, metrics

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="SIEMantics", version="0.1.0", lifespan=lifespan)
app.include_router(alerts.router)
app.include_router(metrics.router)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
