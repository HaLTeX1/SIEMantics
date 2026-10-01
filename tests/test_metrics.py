from types import SimpleNamespace

from app.enums import AlertStatus, GroundTruth
from app.metrics import compute_metrics

TP, FP = GroundTruth.TRUE_POSITIVE, GroundTruth.FALSE_POSITIVE


def _rec(status, ground_truth=None, auto_status=None, escalated_by_id=None, ms=10.0):
    return SimpleNamespace(
        status=status, auto_status=auto_status, ground_truth=ground_truth,
        escalated_by_id=escalated_by_id, processing_time_ms=ms,
    )


def test_confusion_matrix_basic():
    m = compute_metrics([
        _rec(AlertStatus.ESCALATED, TP),
        _rec(AlertStatus.ESCALATED, FP),
        _rec(AlertStatus.SUPPRESSED, FP),
        _rec(AlertStatus.SUPPRESSED, TP),
        _rec(AlertStatus.SUPPRESSED),  # unlabeled
    ])
    assert (m.true_positive, m.false_positive, m.true_negative, m.false_negative) == (1, 1, 1, 1)
    assert m.sample_size == 5
    assert m.labeled_size == 4
    assert m.precision == 0.5
    assert m.recall == 0.5


def test_needs_review_is_a_negative_prediction_and_its_tps_are_counted():
    m = compute_metrics([
        _rec(AlertStatus.NEEDS_REVIEW, TP),
        _rec(AlertStatus.NEEDS_REVIEW, FP),
        _rec(AlertStatus.NEEDS_REVIEW),
    ])
    assert m.false_negative == 1
    assert m.true_negative == 1
    assert m.needs_review_count == 3
    assert m.needs_review_true_positive == 1


def test_manual_escalation_does_not_count_as_automatic_true_positive():
    # status changed to ESCALATED by an analyst; auto_status keeps the system's decision
    m = compute_metrics([
        _rec(AlertStatus.ESCALATED, TP, auto_status=AlertStatus.NEEDS_REVIEW, escalated_by_id=1),
    ])
    assert m.true_positive == 0
    assert m.false_negative == 1
    assert m.needs_review_true_positive == 1
    assert m.manually_escalated_count == 1


def test_records_without_auto_status_fall_back_to_status():
    m = compute_metrics([_rec(AlertStatus.ESCALATED, TP, auto_status=None)])
    assert m.true_positive == 1


def test_error_records_are_excluded_from_processing_time():
    m = compute_metrics([_rec(AlertStatus.ERROR, ms=9999.0), _rec(AlertStatus.SUPPRESSED, ms=10.0)])
    assert m.error_count == 1
    assert m.avg_processing_time_ms == 10.0
