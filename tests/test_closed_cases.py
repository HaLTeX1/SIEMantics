import pytest

from app import pipeline
from app.config import settings

from conftest import process_alert, wazuh_alert

SYNC = "/api/v1/cases/sync"


def escalated(client, alert_id, srcip="198.51.100.1", **extra):
    return process_alert(client, wazuh_alert(alert_id=alert_id, level=13, data={"srcip": srcip}, **extra))


def get(client, display_id):
    return client.get(f"/api/v1/alerts/{display_id}").json()


@pytest.fixture
def triage_calls(monkeypatch) -> list:
    calls: list = []
    real = pipeline.triage_alert

    async def spy(alert, related=None):
        calls.append(alert.alert_id)
        return await real(alert, related)

    monkeypatch.setattr(pipeline, "triage_alert", spy)
    return calls


@pytest.mark.parametrize("synced", [False, True])
def test_alert_after_closure_opens_a_new_case(logged_in, iris, synced):
    first = escalated(logged_in, "c1")
    case_id = first["iris_case_id"]
    iris.closed.add(case_id)
    iris.outcomes[case_id] = 4
    if synced:
        logged_in.post(SYNC)

    second = escalated(logged_in, "c2")
    assert second["iris_case_id"] != case_id and len(iris.calls) == 2
    assert second["correlated_with"] is None
    assert not any(a["case_id"] == case_id for a in iris.added)
    # A lezart eset csoportjaba sem kerul, kulon sorkent latszik.
    assert get(logged_in, second["display_id"])["group"] is None


def test_correlation_continues_in_the_new_open_case(logged_in, iris):
    first = escalated(logged_in, "n1")
    iris.closed.add(first["iris_case_id"])
    second = escalated(logged_in, "n2")
    third = escalated(logged_in, "n3")
    assert third["iris_case_id"] == second["iris_case_id"] != first["iris_case_id"]
    assert third["correlated_with"] == second["display_id"]


def test_duplicate_of_a_closed_case_is_triaged_again(logged_in, iris, monkeypatch, triage_calls):
    monkeypatch.setattr(settings, "dedup_window_hours", 24)
    first = escalated(logged_in, "d1")
    iris.closed.add(first["iris_case_id"])
    iris.outcomes[first["iris_case_id"]] = 2
    repeat = escalated(logged_in, "d2")
    assert triage_calls == ["d1", "d2"]
    assert repeat["triage_engine"] != "dedup" and repeat["iris_case_id"] != first["iris_case_id"]


def test_duplicate_of_an_open_case_still_takes_it_over(logged_in, iris, monkeypatch, triage_calls):
    monkeypatch.setattr(settings, "dedup_window_hours", 24)
    first = escalated(logged_in, "o1")
    repeat = escalated(logged_in, "o2")
    assert triage_calls == ["o1"] and repeat["iris_case_id"] == first["iris_case_id"]


def test_duplicate_of_a_case_closed_as_false_positive_stays_suppressed(logged_in, iris, monkeypatch):
    monkeypatch.setattr(settings, "dedup_window_hours", 24)
    first = escalated(logged_in, "f1")
    iris.closed.add(first["iris_case_id"])
    iris.outcomes[first["iris_case_id"]] = 1
    logged_in.post(SYNC)
    repeat = escalated(logged_in, "f2")
    assert repeat["status"] == "suppressed" and repeat["iris_case_id"] is None


def test_flood_does_not_reuse_a_closed_case(logged_in, iris, monkeypatch, triage_calls):
    monkeypatch.setattr(settings, "flood_threshold", 2)
    first = escalated(logged_in, "x1", srcip="203.0.113.1")
    iris.closed.add(first["iris_case_id"])
    second = escalated(logged_in, "x2", srcip="203.0.113.2")
    assert triage_calls == ["x1", "x2"]
    assert second["triage_engine"] != "flood" and second["iris_case_id"] != first["iris_case_id"]


def test_iris_unavailable_keeps_dedup_working(logged_in, iris, monkeypatch, triage_calls):
    monkeypatch.setattr(settings, "dedup_window_hours", 24)
    first = escalated(logged_in, "u1")

    async def down(case_id):
        raise RuntimeError("iris down")

    monkeypatch.setattr(pipeline.iris_client, "get_case", down)
    repeat = escalated(logged_in, "u2")
    assert triage_calls == ["u1"] and repeat["iris_case_id"] == first["iris_case_id"]
