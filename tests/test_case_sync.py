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


# --- lezarasi annotacio

def test_closure_annotation_is_synced(logged_in, iris):
    alert = escalated(logged_in, "a1")
    case_id = alert["iris_case_id"]
    iris.closed.add(case_id)
    iris.outcomes[case_id] = 2
    iris.annotations[case_id] = "  Ransomware stopped, host reimaged.  "
    logged_in.post(SYNC)
    assert get(logged_in, alert["display_id"])["case_closure_note"] == "Ransomware stopped, host reimaged."


def test_case_info_is_live_and_refreshes_the_note(logged_in, iris):
    alert = escalated(logged_in, "a2")
    case_id = alert["iris_case_id"]
    info = logged_in.get(f"/api/v1/cases/{case_id}").json()
    assert info["closed"] is False and info["closure_annotation"] is None and info["outcome"] == "Unknown"

    # Lezaras, majd az annotacio utolag kerul be: a szinkron mar nem nezi, a reszletpanel igen.
    iris.closed.add(case_id)
    iris.outcomes[case_id] = 5
    logged_in.post(SYNC)
    iris.annotations[case_id] = "Admin maintenance window"
    info = logged_in.get(f"/api/v1/cases/{case_id}").json()
    assert info["closed"] is True and info["outcome"] == "Legitimate"
    assert info["closure_annotation"] == "Admin maintenance window"
    record = get(logged_in, alert["display_id"])
    assert record["case_closure_note"] == "Admin maintenance window" and record["ground_truth"] == "false_positive"


def test_case_info_unknown_case(logged_in, iris):
    assert logged_in.get("/api/v1/cases/987654").status_code == 404


def test_case_info_closes_unsynced_case(logged_in, iris):
    alert = escalated(logged_in, "a3")
    iris.closed.add(alert["iris_case_id"])
    iris.outcomes[alert["iris_case_id"]] = 4
    logged_in.get(f"/api/v1/cases/{alert['iris_case_id']}")
    record = get(logged_in, alert["display_id"])
    assert record["case_closed_at"] is not None and record["ground_truth"] == "true_positive"


def test_false_positive_close_writes_annotation(logged_in, iris):
    alert = escalated(logged_in, "a4")
    case_id = alert["iris_case_id"]
    logged_in.post(f"/api/v1/cases/{case_id}/false-positive", json={"reason": "vulnerability scanner"})
    assert iris.annotations[case_id] == "False positive (admin, SIEMantics): vulnerability scanner"
    assert get(logged_in, alert["display_id"])["case_closure_note"] == iris.annotations[case_id]


def test_false_positive_close_without_closure_field(logged_in, iris):
    # Ha az IRIS-ben nincs felveve a mezo, a lezaras attol meg sikeres.
    iris.has_closure_field = False
    alert = escalated(logged_in, "a5")
    res = logged_in.post(f"/api/v1/cases/{alert['iris_case_id']}/false-positive", json={})
    assert res.status_code == 200 and alert["iris_case_id"] in iris.closed


# --- kimaradt Outcome: annotacio es utolagos kitoltes

def test_annotation_is_the_fallback_when_outcome_is_unknown():
    def case(note, status_id=0):
        return {"status_id": status_id,
                "custom_attributes": {"Closure": {"Closure annotation": {"value": note}}}}

    assert case_disposition(case("IP addresses blocked for 7 days. TPNI.")) == GroundTruth.TRUE_POSITIVE
    assert case_disposition(case("true positive, host reimaged")) == GroundTruth.TRUE_POSITIVE
    assert case_disposition(case("FP: backup job")) == GroundTruth.FALSE_POSITIVE
    # Ellentmondas vagy jeloles nelkul nincs dontes; a kitoltott Outcome elsobbseget elvez.
    assert case_disposition(case("not FP, it is a TP")) is None
    assert case_disposition(case("blocked the IP")) is None
    assert case_disposition(case("TPNI", status_id=1)) == GroundTruth.FALSE_POSITIVE


def test_outcome_set_after_closing_is_picked_up(logged_in, iris):
    alert = escalated(logged_in, "late1")
    case_id = alert["iris_case_id"]
    iris.closed.add(case_id)
    logged_in.post(SYNC)
    record = get(logged_in, alert["display_id"])
    assert record["case_closed_at"] is not None and record["ground_truth"] is None

    # Az Outcome csak a lezaras utan kerul ra: a kovetkezo szinkron atveszi.
    iris.outcomes[case_id] = 2
    body = logged_in.post(SYNC).json()
    assert body["labeled"] == [alert["display_id"]]
    assert get(logged_in, alert["display_id"])["ground_truth"] == "true_positive"
    # Itelet utan mar nem figyeli tovabb.
    assert logged_in.post(SYNC).json()["checked"] == 0


def test_late_annotation_is_picked_up_by_the_live_view(logged_in, iris):
    alert = escalated(logged_in, "late2")
    case_id = alert["iris_case_id"]
    iris.closed.add(case_id)
    logged_in.post(SYNC)
    iris.annotations[case_id] = "IP blocked. TPNI"
    logged_in.get(f"/api/v1/cases/{case_id}")
    record = get(logged_in, alert["display_id"])
    assert record["ground_truth"] == "true_positive" and record["case_closure_note"] == "IP blocked. TPNI"


def test_late_outcome_does_not_override_an_analyst_label(logged_in, iris):
    alert = escalated(logged_in, "late3")
    case_id = alert["iris_case_id"]
    iris.closed.add(case_id)
    logged_in.post(SYNC)
    logged_in.patch(f"/api/v1/alerts/{alert['display_id']}/label", json={"ground_truth": "false_positive"})
    iris.outcomes[case_id] = 2
    logged_in.post(SYNC)
    assert get(logged_in, alert["display_id"])["ground_truth"] == "false_positive"
