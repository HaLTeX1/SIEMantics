# Visszajatszo meres: a cimkezett, onallo dontesu riasztasok ujratriazsa a mostani prompttal es kontextussal.
# Az adatbazist nem modositja. Futtatas a szerveren: python -m app.eval_replay --limit 50

import argparse
import asyncio
import json
from collections import Counter, defaultdict

from sqlalchemy import select

from app.db import async_session
from app.enums import AlertStatus, GroundTruth
from app.guardrails import Evidence, decide_status
from app.llm_engine import LlmUnavailable, llm_configured, second_opinion_enabled, triage_alert
from app.metrics import calibration
from app.models import AlertRecord
from app.pipeline import (
    alert_from_record,
    analyst_history,
    environment_context,
    needs_second_opinion,
    related_alerts,
    second_opinion,
)

# Masolt dontesek es nem predikciok: ezeket nem jatsszuk vissza.
_SKIP_ENGINES = ("dedup", "flood", "suppression", "analyst", "context")


def _outcome(escalated: bool, truth: GroundTruth) -> str:
    actual = truth == GroundTruth.TRUE_POSITIVE
    return ("TP" if actual else "FP") if escalated else ("FN" if actual else "TN")


def _summary(counter: Counter) -> dict:
    tp, fp, tn, fn = (counter[k] for k in ("TP", "FP", "TN", "FN"))
    n = tp + fp + tn + fn
    return {
        "n": n, "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "accuracy": round((tp + tn) / n, 3) if n else None,
        "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else None,
        "recall": round(tp / (tp + fn), 3) if tp + fn else None,
    }


async def _candidates(limit: int | None) -> list[AlertRecord]:
    async with async_session() as session:
        result = await session.execute(
            select(AlertRecord)
            .where(AlertRecord.ground_truth.is_not(None), AlertRecord.raw_payload.is_not(None))
            .order_by(AlertRecord.received_at)
        )
        # Csak emberi itelettel cimkezett, onallo dontesek.
        records = [r for r in result.scalars() if r.triage_engine not in _SKIP_ENGINES and r.label_source is None]
    return records[-limit:] if limit else records


async def replay(limit: int | None, delay: float, out: str | None, use_second_opinion: bool = False) -> dict:
    if not llm_configured():
        raise SystemExit("OpenRouter is not configured (OPENROUTER_API_KEY), nothing to measure")
    records = await _candidates(limit)
    print(f"replaying {len(records)} labeled alert(s); the database is not modified")
    before, after = Counter(), Counter()
    by_model: dict[str, Counter] = defaultdict(Counter)
    samples: list[tuple[float, bool, bool]] = []
    rows = []
    if use_second_opinion and not second_opinion_enabled():
        print("second opinion requested but SECOND_OPINION_MODEL is not set to a free model, skipping it")
    for index, record in enumerate(records, 1):
        old_escalated = (record.auto_status or record.status) == AlertStatus.ESCALATED
        async with async_session() as session:
            alert = alert_from_record(record)
            # A riasztas idejeben ismert itelet latszik csak, kulonben a meres tul optimista lenne.
            related = await related_alerts(session, alert, record.received_at, exclude_id=record.id,
                                           as_of=record.received_at)
            environment = await environment_context(session, alert)
            history = await analyst_history(session, record, as_of=record.received_at)
        try:
            triage = await triage_alert(alert, related, environment, history)
        except LlmUnavailable as exc:
            print(f"stopping at {index - 1}/{len(records)}: LLM unavailable ({exc})")
            break
        evidence = Evidence.from_history(history)
        if use_second_opinion and needs_second_opinion(triage, evidence):
            evidence.second_opinion_fp, _ = await second_opinion(alert, related, environment, history)
        status, reason = decide_status(alert, triage, evidence)
        samples.append((triage.confidence, triage.is_true_positive, record.ground_truth == GroundTruth.TRUE_POSITIVE))
        new_escalated = status == AlertStatus.ESCALATED
        old, new = _outcome(old_escalated, record.ground_truth), _outcome(new_escalated, record.ground_truth)
        before[old] += 1
        after[new] += 1
        by_model[triage.model or "-"][new] += 1
        rows.append({
            "id": record.display_id, "rule_id": record.rule_id, "rule": record.rule_description[:90],
            "host": record.agent_name, "truth": record.ground_truth.value,
            "before": {"engine": record.triage_engine, "outcome": old},
            "after": {"status": status.value, "outcome": new, "confidence": triage.confidence,
                      "model": triage.model, "review_reason": reason, "summary": triage.summary},
        })
        mark = "fixed" if old in ("FP", "FN") and new in ("TP", "TN") else "BROKE" if new in ("FP", "FN") and old in ("TP", "TN") else ""
        print(f"[{index}/{len(records)}] {record.display_id} {record.rule_description[:60]!r}: {old} -> {new} {mark}")
        if delay:
            await asyncio.sleep(delay)

    report = {
        "before": _summary(before),
        "after": _summary(after),
        "after_by_model": {model: _summary(c) for model, c in by_model.items()},
        "confidence_calibration": calibration(samples).model_dump(),
        "alerts": rows,
    }
    print(json.dumps({k: v for k, v in report.items() if k != "alerts"}, indent=2))
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        print(f"details written to {out}")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay labeled alerts through the current triage prompt.")
    parser.add_argument("--limit", type=int, default=None, help="only the N most recent labeled alerts")
    parser.add_argument("--delay", type=float, default=4.0, help="seconds between LLM calls (free tier rate limit)")
    parser.add_argument("--out", default=None, help="write the per-alert details to this JSON file")
    parser.add_argument("--second-opinion", action="store_true", help="ask SECOND_OPINION_MODEL like the pipeline does")
    args = parser.parse_args()
    asyncio.run(replay(args.limit, args.delay, args.out, args.second_opinion))


if __name__ == "__main__":
    main()
