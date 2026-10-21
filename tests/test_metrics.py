from types import SimpleNamespace

from app.enums import AlertStatus, GroundTruth
from app.metrics import compute_metrics

TP, FP = GroundTruth.TRUE_POSITIVE, GroundTruth.FALSE_POSITIVE


def _rec(status, ground_truth=None, auto_status=None, escalated_by_id=None, ms=10.0, engine="openrouter",
         confidence=None, llm_tp=None):
    return SimpleNamespace(
        status=status, auto_status=auto_status, ground_truth=ground_truth,
        escalated_by_id=escalated_by_id, processing_time_ms=ms, triage_engine=engine,
        llm_confidence=confidence, llm_is_true_positive=llm_tp,
    )


def test_confusion_matrix_basic():
    m = compute_metrics([
        _rec(AlertStatus.ESCALATED, TP),
        _rec(AlertStatus.ESCALATED, FP),
        _rec(AlertStatus.SUPPRESSED, FP),
        _rec(AlertStatus.SUPPRESSED, TP),
        _rec(AlertStatus.SUPPRESSED),  # cimkezetlen
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
    # Analyst ESCALATED-re allitotta, az auto_status a rendszer dontese.
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


def test_untriaged_records_are_not_predictions():
    # Pl. a hurok riasztasai: triazs nelkul, kesobb osszevonva (escalated) es FP-re cimkezve.
    m = compute_metrics([
        _rec(AlertStatus.ESCALATED, FP, auto_status=AlertStatus.ERROR, escalated_by_id=1, ms=0.0),
        _rec(AlertStatus.SUPPRESSED, FP, ms=20.0),
    ])
    assert m.true_negative == 1 and m.labeled_size == 1
    assert m.error_count == 1 and m.manually_escalated_count == 0
    assert m.median_processing_time_ms == 20.0


def test_error_records_are_excluded_from_processing_time():
    m = compute_metrics([_rec(AlertStatus.ERROR, ms=9999.0), _rec(AlertStatus.SUPPRESSED, ms=10.0)])
    assert m.error_count == 1
    assert m.avg_processing_time_ms == 10.0


def test_processing_time_uses_independent_decisions_only():
    # A dedup masolat ms alatt kesz, a valos triazsido az LLM-e.
    m = compute_metrics([
        _rec(AlertStatus.SUPPRESSED, ms=40000.0),
        _rec(AlertStatus.ESCALATED, ms=60000.0),
        *[_rec(AlertStatus.SUPPRESSED, ms=20.0, engine="dedup") for _ in range(5)],
    ])
    assert m.median_processing_time_ms == 50000.0
    assert m.by_engine["dedup"].median_processing_time_ms == 20.0
    assert m.by_engine["openrouter"].p95_processing_time_ms == 60000.0
    assert m.independent.avg_processing_time_ms == 50000.0


def test_mock_engine_decisions_are_excluded():
    m = compute_metrics([_rec(AlertStatus.ESCALATED, FP, engine="mock", ms=5.0), _rec(AlertStatus.ESCALATED, TP)])
    assert m.sample_size == 1 and m.false_positive == 0
    assert "mock" not in m.by_engine
    assert m.median_processing_time_ms == 10.0


def test_alerts_closed_before_triage_are_not_predictions():
    # Flood: az elemzo a varakozo riasztasokat triazs elott lezarta.
    m = compute_metrics([
        _rec(AlertStatus.SUPPRESSED, FP),
        _rec(AlertStatus.SUPPRESSED, FP, engine="analyst"),
    ])
    assert m.sample_size == 1 and m.true_negative == 1


def test_independent_metrics_exclude_copied_decisions():
    # Egy helyes dontes 3 dedup masolata ne fujja fel a pontossagot.
    m = compute_metrics([
        _rec(AlertStatus.ESCALATED, FP),
        _rec(AlertStatus.ESCALATED, TP),
        *[_rec(AlertStatus.ESCALATED, TP, engine="dedup") for _ in range(3)],
    ])
    assert m.accuracy == 0.8
    assert m.independent.labeled_size == 2 and m.independent.accuracy == 0.5
    assert m.by_engine["dedup"].labeled_size == 3 and m.by_engine["openrouter"].false_positive_rate == 1.0


def test_calibration_reports_buckets_and_a_threshold_only_when_it_separates():
    from app.metrics import calibration

    # Informativ confidence: 0.9 felett minden FP itelet helyes, alatta fele.
    good = [(0.95, False, False)] * 6 + [(0.6, False, True), (0.6, False, False)]
    report = calibration(good)
    assert report.suggested_fp_threshold == 0.95
    assert next(b for b in report.buckets if b.range == "0.9-1.0").accuracy == 1.0

    # Az eles mintahoz hasonlo: a teves es a helyes itelet ugyanott van, nincs hasznalhato kuszob.
    flat = [(0.9, True, False)] * 5 + [(0.9, True, True)] * 2 + [(0.9, False, True)] * 3 + [(0.9, False, False)] * 3
    report = calibration(flat)
    assert report.suggested_fp_threshold is None
    assert report.mean_confidence_correct == report.mean_confidence_wrong == 0.9


def test_metrics_include_calibration_of_labeled_llm_decisions():
    m = compute_metrics([
        _rec(AlertStatus.ESCALATED, FP, confidence=0.9, llm_tp=True),
        _rec(AlertStatus.ESCALATED, TP, confidence=0.9, llm_tp=True),
        _rec(AlertStatus.ESCALATED, TP, engine="dedup", confidence=0.9, llm_tp=True),
    ])
    # Csak az LLM sajat, cimkezett dontesei; a dedup masolat nem.
    assert m.calibration.sample_size == 2
    assert m.calibration.mean_confidence_wrong == 0.9 and m.calibration.current_threshold == 0.7
