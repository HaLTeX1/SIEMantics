# Elo adatok a riportokhoz: a szakdolgozat 4. tablazata a dontesnaplobol, minden megnyitaskor.

import re
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.enums import AlertStatus
from app.metrics import compute_metrics
from app.models import AlertRecord

# Valodi Wazuh riasztas azonositoja; a webhookos tesztek szoveges alert_id-ja kimarad.
_WAZUH_ID = re.compile(r"^\d+\.\d+$")


def _num(value: float, digits: int = 1) -> str:
    return f"{value:.{digits}f}".replace(".", ",")


def _pct(value: float | None) -> str:
    return "–" if value is None else f"{_num(value * 100)} %"


def _sec(ms: float | None) -> str:
    return "–" if ms is None else f"{_num(ms / 1000)} s"


async def table4(session: AsyncSession) -> dict[str, str]:
    records = [r for r in (await session.scalars(select(AlertRecord))).all() if _WAZUH_ID.match(r.alert_id or "")]
    m = compute_metrics(records)
    # Feldolgozott: triazs dontest kapott (a triazs nelkuli es a meg sorban allo nem).
    processed = sum(1 for r in records if (r.auto_status or r.status) not in (AlertStatus.ERROR, AlertStatus.QUEUED))
    return {
        "processed": f"{processed} db",
        "labeled": f"{m.labeled_size} db",
        "tp": str(m.true_positive),
        "fp": str(m.false_positive),
        "tn": str(m.true_negative),
        "fn": str(m.false_negative),
        "scores": " / ".join(_pct(v) for v in (m.accuracy, m.precision, m.recall, m.f1_score)),
        "fpr": _pct(m.false_positive_rate),
        "times": " / ".join(_sec(v) for v in (m.avg_processing_time_ms, m.median_processing_time_ms,
                                               m.p95_processing_time_ms)),
        "review": str(m.needs_review_count),
        "updated": datetime.utcnow().strftime("%Y. %m. %d. %H:%M UTC"),
    }


BUILDERS = {"4-tablazat": table4}
