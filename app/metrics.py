from statistics import mean, median

from app.enums import AlertStatus, GroundTruth
from app.models import AlertRecord
from app.schemas import TriageMetrics


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = min(int(len(ordered) * pct), len(ordered) - 1)
    return ordered[idx]


def compute_metrics(records: list[AlertRecord]) -> TriageMetrics:
    tp = fp = tn = fn = 0

    for record in records:
        if record.ground_truth is None:
            continue
        predicted_positive = record.status == AlertStatus.ESCALATED
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
    processing_times = [r.processing_time_ms for r in records if r.status != AlertStatus.ERROR]
    error_count = sum(1 for r in records if r.status == AlertStatus.ERROR)

    return TriageMetrics(
        sample_size=len(records),
        labeled_size=labeled_total,
        error_count=error_count,
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
