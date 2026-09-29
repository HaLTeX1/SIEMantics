from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.db import get_session
from app.metrics import compute_metrics
from app.repository import list_all_records
from app.schemas import TriageMetrics

router = APIRouter(prefix="/api/v1", tags=["metrics"], dependencies=[Depends(get_current_user)])


@router.get("/metrics", response_model=TriageMetrics)
async def get_metrics(session: AsyncSession = Depends(get_session)):
    records = await list_all_records(session)
    return compute_metrics(records)
