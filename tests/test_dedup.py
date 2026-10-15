import pytest

from app import pipeline
from app.config import settings
from app.fingerprint import alert_fingerprint

from conftest import WEBHOOK_HEADERS, process_alert, wazuh_alert

VSCODE = ('"powershell.exe" -NoProfile -Command "Add-AppxPackage -Path \'C:\\Users\\info\\AppData\\Local\\Programs\\'
          'Microsoft VS Code\\{dir}\\appx\\code_x64.appx\' Microsoft.VisualStudioCode_1.0.{ver}_neutral"')


def ps_alert(alert_id, dir_hash="7baac39ec3", ver="141.0", host="UL_RL_WRKS_W11", level=10):
    # Windows PowerShell riasztas forras IP nelkul, a VS Code frissiteshez hasonloan.
    payload = wazuh_alert(alert_id=alert_id, level=level, agent={"id": "009", "name": host},
                          data={"win": {"eventdata": {"commandLine": VSCODE.format(dir=dir_hash, ver=ver)}}})
    payload["rule"]["id"] = "100201"
    return payload


@pytest.fixture
def dedup(monkeypatch):
    monkeypatch.setattr(settings, "dedup_window_hours", 24)


@pytest.fixture
def triage_calls(monkeypatch) -> list:
    calls: list = []
    real = pipeline.triage_alert

    async def spy(alert, related=None, *args):
        calls.append(alert.alert_id)
        return await real(alert, related, *args)

    monkeypatch.setattr(pipeline, "triage_alert", spy)
    return calls


# --- ujjlenyomat

def test_fingerprint_ignores_versions_hashes_and_numbers():
    a = alert_fingerprint(ps_alert("x1", dir_hash="7baac39ec3", ver="141.0"))
    b = alert_fingerprint(ps_alert("x2", dir_hash="16507d91be", ver="141.1"))
    assert a == b
    assert alert_fingerprint(ps_alert("x3", host="other")) != a


def test_fingerprint_keeps_ip_addresses_apart():
    a = alert_fingerprint(wazuh_alert(data={"srcip": "10.64.0.90"}))
    assert a != alert_fingerprint(wazuh_alert(data={"srcip": "10.64.0.91"}))
    assert a == alert_fingerprint(wazuh_alert(alert_id="other", data={"srcip": "10.64.0.90"}))


# --- duplikatum-szures

def test_duplicate_takes_over_the_decision_without_llm(logged_in, iris, dedup, triage_calls):
    first = process_alert(logged_in, wazuh_alert(alert_id="d1", level=13))
    second = process_alert(logged_in, wazuh_alert(alert_id="d2", level=13))

    assert triage_calls == ["d1"]
    assert second["triage_engine"] == "dedup" and second["status"] == "escalated"
    assert second["iris_case_id"] == first["iris_case_id"]
    assert second["correlated_with"] == first["display_id"] and second["group"] == first["display_id"]
    # Az IRIS esetbe nem kerul uj note az ismetlodesrol.
    assert len(iris.calls) == 1 and iris.added == []


def test_duplicate_of_a_known_false_positive_is_suppressed(logged_in, iris, dedup, triage_calls):
    first = process_alert(logged_in, ps_alert("v1"))
    logged_in.patch(f"/api/v1/alerts/{first['display_id']}/label", json={"ground_truth": "false_positive"})

    second = process_alert(logged_in, ps_alert("v2", dir_hash="16507d91be", ver="141.1"))
    assert triage_calls == ["v1"]
    assert second["status"] == "suppressed" and second["auto_status"] == "suppressed"
    assert "labeled false positive" in second["review_reason"]
    # Automatikus cimke nincs, a metrikat nem torzitja.
    assert second["ground_truth"] is None
    assert second["group"] == first["display_id"]


def test_different_source_is_not_a_duplicate(logged_in, iris, dedup, triage_calls):
    process_alert(logged_in, wazuh_alert(alert_id="s1", level=13, data={"srcip": "198.51.100.1"}))
    process_alert(logged_in, wazuh_alert(alert_id="s2", level=13, data={"srcip": "198.51.100.2"}))
    assert triage_calls == ["s1", "s2"]


def test_dedup_can_be_disabled(logged_in, iris, triage_calls):
    process_alert(logged_in, wazuh_alert(alert_id="o1", level=13))
    process_alert(logged_in, wazuh_alert(alert_id="o2", level=13))
    assert triage_calls == ["o1", "o2"]


def test_wait_mode_answers_for_a_duplicate(logged_in, iris, dedup):
    process_alert(logged_in, wazuh_alert(alert_id="w1", level=2))
    body = logged_in.post("/api/v1/alerts?wait=true", json=wazuh_alert(alert_id="w2", level=2),
                          headers=WEBHOOK_HEADERS).json()
    assert body["status"] == "suppressed" and body["triage"]["engine"] == "dedup"


# --- automatikus csoportositas

def test_burst_on_one_host_is_grouped_automatically(logged_in, iris):
    # Egy telepites riasztasai forras IP nelkul: egy elnyomott es egy eszkalalt, mas szabaly.
    host = {"id": "013", "name": "zabbix"}
    quiet = wazuh_alert(alert_id="b1", level=2, agent=host, data={})
    loud = wazuh_alert(alert_id="b2", level=13, agent=host, data={})
    loud["rule"]["id"] = "5902"
    first = process_alert(logged_in, quiet)
    second = process_alert(logged_in, loud)
    record = logged_in.get(f"/api/v1/alerts/{second['display_id']}").json()
    assert record["group"] == first["display_id"] and record["group_size"] == 2
