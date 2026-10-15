from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_context_editor
from app.db import get_session
from app.enums import AlertStatus, GroundTruth
from app.models import AlertRecord
from app.wazuh_client import WazuhApiError, wazuh_client

router = APIRouter(prefix="/api/v1/wazuh", tags=["wazuh"], dependencies=[Depends(require_context_editor)])

_STATS_DAYS = 30
_SORTS = {"id": "+id", "-id": "-id", "level": "+level", "-level": "-level"}


async def _rule_stats(session: AsyncSession, rule_ids: list[str] | None, since: datetime) -> dict[str, dict]:
    # SIEMantics riasztasok szabalyonkent: darab, eszkalalt, felulvizsgalat, elemzoi TP/FP, utolso.
    stmt = (
        select(
            AlertRecord.rule_id,
            func.count(),
            func.sum(case((AlertRecord.status == AlertStatus.ESCALATED, 1), else_=0)),
            func.sum(case((AlertRecord.status == AlertStatus.NEEDS_REVIEW, 1), else_=0)),
            func.sum(case((AlertRecord.ground_truth == GroundTruth.TRUE_POSITIVE, 1), else_=0)),
            func.sum(case((AlertRecord.ground_truth == GroundTruth.FALSE_POSITIVE, 1), else_=0)),
            func.max(AlertRecord.received_at),
        )
        .where(AlertRecord.received_at >= since, AlertRecord.rule_id.is_not(None))
        .group_by(AlertRecord.rule_id)
    )
    if rule_ids is not None:
        stmt = stmt.where(AlertRecord.rule_id.in_(rule_ids))
    rows = (await session.execute(stmt)).all()
    return {
        str(rid): {"alerts": n, "escalated": int(esc or 0), "needs_review": int(rev or 0),
                   "true_positive": int(tp or 0), "false_positive": int(fp or 0), "last_seen": last}
        for rid, n, esc, rev, tp, fp, last in rows
    }


@router.get("/rules")
async def list_rules(
    search: str = "",
    level_min: int = 0,
    group: str = "",
    seen_only: bool = True,
    sort: str = "id",
    offset: int = 0,
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
):
    # A Wazuh-ban definialt szabalyok, mellettuk a SIEMantics-beli elofordulasuk az elmult 30 napbol.
    if not wazuh_client.enabled:
        raise HTTPException(status_code=503, detail="Wazuh API is not configured")
    since = datetime.utcnow() - timedelta(days=_STATS_DAYS)
    params: dict = {"limit": max(1, min(limit, 200)), "offset": max(offset, 0), "sort": _SORTS.get(sort, "+id")}
    if search.strip():
        params["search"] = search.strip()
    if level_min > 0:
        params["level"] = f"{min(level_min, 16)}-16"
    if group.strip():
        params["group"] = group.strip()

    stats: dict[str, dict] = {}
    if seen_only:
        # Csak a SIEMantics-be bekerult szabalyok: ezeknel van mit hangolni.
        stats = await _rule_stats(session, None, since)
        if not stats:
            return {"total": 0, "items": [], "stats_days": _STATS_DAYS}
        params["rule_ids"] = ",".join(sorted(stats, key=lambda r: int(r) if r.isdigit() else 0))
    try:
        items, total = await wazuh_client.list_rules(params)
    except WazuhApiError as exc:
        if exc.status_code == 403:
            raise HTTPException(status_code=403, detail="the Wazuh API user needs the rules:read permission") from exc
        raise HTTPException(status_code=502, detail=f"Wazuh API error: {exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh API unavailable: {exc}") from exc

    if not seen_only:
        stats = await _rule_stats(session, [str(i.get("id")) for i in items], since)
    out = []
    for item in items:
        rid = str(item.get("id"))
        out.append({
            "id": item.get("id"),
            "level": item.get("level"),
            "description": item.get("description"),
            "groups": item.get("groups") or [],
            "mitre": item.get("mitre") or [],
            "filename": item.get("filename"),
            "relative_dirname": item.get("relative_dirname"),
            "status": item.get("status"),
            "details": item.get("details") or {},
            "compliance": {k: item.get(k) for k in ("pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13")
                           if item.get(k)},
            "siemantics": stats.get(rid),
        })
    return {"total": total, "items": out, "stats_days": _STATS_DAYS}
