from app.case_actions import case_disposition
from app.enums import GroundTruth

from conftest import process_alert, wazuh_alert

SYNC = "/api/v1/cases/sync"


def get(client, display_id):
    return client.get(f"/api/v1/alerts/{display_id}").json()


def escalated(client, alert_id, srcip="198.51.100.1"):
    return process_alert(client, wazuh_alert(alert_id=alert_id, level=13, data={"srcip": srcip}))


def test_outcome_mapping():
    assert case_disposition({"status_id": 2}) == GroundTruth.TRUE_POSITIVE
    assert case_disposition({"status_id": "4"}) == GroundTruth.TRUE_POSITIVE
    assert case_disposition({"status_id": 1}) == GroundTruth.FALSE_POSITIVE
    assert case_disposition({"status_id": 5}) == GroundTruth.FALSE_POSITIVE
    assert case_disposition({"status_id": 3}) is None
    assert case_disposition({"status_id": 0, "case_tags": "wazuh,false-positive"}) == GroundTruth.FALSE_POSITIVE
    assert case_disposition({}) is None


def test_case_closed_in_iris_updates_disposition(logged_in, iris):
    first = escalated(logged_in, "c1")
    # Ugyanaz az IP es szabaly: ugyanabba az esetbe kerul.
    second = escalated(logged_in, "c2")
    case_id = first["iris_case_id"]
    assert second["iris_case_id"] == case_id

    # Meg nyitott: nincs valtozas.
    body = logged_in.post(SYNC).json()
    assert body == {"checked": 1, "closed_cases": [], "labeled": []}

    iris.closed.add(case_id)
    iris.outcomes[case_id] = 4
    body = logged_in.post(SYNC).json()
    assert body["closed_cases"] == [case_id]
    assert sorted(body["labeled"]) == sorted([first["display_id"], second["display_id"]])
    record = get(logged_in, first["display_id"])
    assert record["ground_truth"] == "true_positive" and record["case_closed_at"] is not None

    # Lezart esetet nem kerdez le ujra, a kesobbi kezi cimke megmarad.
    logged_in.patch(f"/api/v1/alerts/{first['display_id']}/label", json={"ground_truth": "false_positive"})
    assert logged_in.post(SYNC).json()["checked"] == 0
    assert get(logged_in, first["display_id"])["ground_truth"] == "false_positive"


def test_iris_outcome_overrides_an_earlier_label(logged_in, iris):
    alert = escalated(logged_in, "o1")
    logged_in.patch(f"/api/v1/alerts/{alert['display_id']}/label", json={"ground_truth": "true_positive"})
    iris.closed.add(alert["iris_case_id"])
    iris.outcomes[alert["iris_case_id"]] = 1
    logged_in.post(SYNC)
    assert get(logged_in, alert["display_id"])["ground_truth"] == "false_positive"


def test_closed_without_outcome_keeps_disposition(logged_in, iris):
    alert = escalated(logged_in, "n1")
    iris.closed.add(alert["iris_case_id"])
    assert logged_in.post(SYNC).json()["labeled"] == []
    record = get(logged_in, alert["display_id"])
    assert record["ground_truth"] is None and record["case_closed_at"] is not None


def test_iris_unavailable_skips_cases(logged_in, iris):
    escalated(logged_in, "u1")
    iris.fail = True
    assert logged_in.post(SYNC).json() == {"checked": 0, "closed_cases": [], "labeled": []}


def test_false_positive_close_sets_iris_outcome(logged_in, iris):
    alert = escalated(logged_in, "f1")
    case_id = alert["iris_case_id"]
    logged_in.post(f"/api/v1/cases/{case_id}/false-positive", json={})
    assert iris.outcomes[case_id] == 1
    assert get(logged_in, alert["display_id"])["case_closed_at"] is not None
    # SIEMantics-bol lezarva: a szinkron mar nem kerdezi le.
    assert logged_in.post(SYNC).json()["checked"] == 0
