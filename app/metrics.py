from statistics import mean, median

from app.enums import AlertStatus, GroundTruth
from app.models import AlertRecord
from app.schemas import EngineMetrics, TriageMetrics


# Elemzo altal triazs elott lezart, illetve csak kontextuskent tarolt rekordok.
_NOT_PREDICTIONS = ("analyst", "context")


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = min(int(len(ordered) * pct), len(ordered) - 1)
    return ordered[idx]


def _automatic_status(record: AlertRecord) -> AlertStatus:
    # A rendszer sajat dontese; a kezi eszkalacio nem szamit helyes predikcionak.
    return record.auto_status or record.status


def _decided(record: AlertRecord) -> bool:
    # Volt triazs dontes; a triazs nelkuli vagy sikertelen rekord nem predikcio.
    return _automatic_status(record) != AlertStatus.ERROR


# Masik riasztas dontesenek masolata vagy elemzoi szabaly: nem onallo predikcio.
_COPIED_DECISIONS = ("dedup", "flood", "suppression")


def _confusion(records: list[AlertRecord]) -> tuple[int, int, int, int]:
    tp = fp = tn = fn = 0
    for record in records:
        if record.ground_truth is None or not _decided(record):
            continue
        predicted = _automatic_status(record) == AlertStatus.ESCALATED
        actual = record.ground_truth == GroundTruth.TRUE_POSITIVE
        if predicted and actual:
            tp += 1
        elif predicted:
            fp += 1
        elif actual:
            fn += 1
        else:
            tn += 1
    return tp, fp, tn, fn


def _scores(records: list[AlertRecord]) -> EngineMetrics:
    tp, fp, tn, fn = _confusion(records)
    labeled = tp + fp + tn + fn
    return EngineMetrics(
        sample_size=len(records),
        labeled_size=labeled,
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
        accuracy=(tp + tn) / labeled if labeled else None,
        false_positive_rate=fp / (fp + tn) if (fp + tn) else None,
        recall=tp / (tp + fn) if (tp + fn) else None,
    )


def compute_metrics(records: list[AlertRecord]) -> TriageMetrics:
    # Meg nincs triazsolva, vagy az elemzo triazs elott lezarta: nincs mit kiertekelni.
    records = [r for r in records if r.status != AlertStatus.QUEUED and r.triage_engine not in _NOT_PREDICTIONS]
    decided = [r for r in records if _decided(r)]
    tp = fp = tn = fn = 0
    review_true_positive = 0

    for record in decided:
        if record.ground_truth is None:
            continue
        # NEEDS_REVIEW negativ predikcio; a TP-k kozuluk a review sor altal elkapott FN-ek.
        auto_status = _automatic_status(record)
        if auto_status == AlertStatus.NEEDS_REVIEW and record.ground_truth == GroundTruth.TRUE_POSITIVE:
            review_true_positive += 1
        predicted_positive = auto_status == AlertStatus.ESCALATED
        actual_positive = record.ground_truth == GroundTruth.TRUE_POSITIVE

        if predicted_positive and actual_positive:
            tp += 1
        elif predicted_positive and not actual_positive:
            fp += 1
        elif not predicted_positive and not actual_positive:
            tn += 1
        else:
            fn += 1

    labeled_total = tp + fp + tn + fn
    processing_times = [r.processing_time_ms for r in decided if r.status != AlertStatus.ERROR]
    error_count = sum(1 for r in records if r.status == AlertStatus.ERROR or not _decided(r))
    needs_review_count = sum(1 for r in decided if _automatic_status(r) == AlertStatus.NEEDS_REVIEW)
    manually_escalated_count = sum(1 for r in decided if r.escalated_by_id is not None)

    # Az ismetlodesek (dedup, flood) felfujjak az osszesitett pontossagot, ezert kulon is.
    engines = sorted({r.triage_engine for r in decided if r.triage_engine})
    by_engine = {engine: _scores([r for r in decided if r.triage_engine == engine]) for engine in engines}
    independent = _scores([r for r in decided if r.triage_engine not in _COPIED_DECISIONS])

    return TriageMetrics(
        independent=independent,
        by_engine=by_engine,
        sample_size=len(records),
        labeled_size=labeled_total,
        error_count=error_count,
        needs_review_count=needs_review_count,
        needs_review_true_positive=review_true_positive,
        manually_escalated_count=manually_escalated_count,
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
        accuracy=(tp + tn) / labeled_total if labeled_total else None,
        precision=tp / (tp + fp) if (tp + fp) else None,
        recall=tp / (tp + fn) if (tp + fn) else None,
        f1_score=(2 * tp) / (2 * tp + fp + fn) if (2 * tp + fp + fn) else None,
        false_positive_rate=fp / (fp + tn) if (fp + tn) else None,
        avg_processing_time_ms=mean(processing_times) if processing_times else None,
        median_processing_time_ms=median(processing_times) if processing_times else None,
        p95_processing_time_ms=_percentile(processing_times, 0.95),
    )
