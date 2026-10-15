import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.wazuh_client import WazuhApiError, wazuh_client

from conftest import process_alert, wazuh_alert

RULES = {
    "5763": {"id": 5763, "level": 10, "description": "sshd: brute force", "groups": ["syslog", "sshd"],
             "mitre": ["T1110"], "filename": "0095-sshd_rules.xml", "relative_dirname": "ruleset/rules",
             "status": "enabled", "details": {"if_matched_sid": "5760", "frequency": "8"}, "pci_dss": ["11.4"]},
    "100": {"id": 100, "level": 3, "description": "Test rule", "groups": ["local"], "filename": "local_rules.xml",
            "relative_dirname": "etc/rules", "status": "enabled", "details": {"match": "benign"}},
    "5902": {"id": 5902, "level": 8, "description": "New user added", "groups": ["adduser"],
             "filename": "0020-syslog_rules.xml", "relative_dirname": "ruleset/rules", "status": "enabled", "details": {}},
}


@pytest.fixture
def wazuh(monkeypatch):
    state = {"params": [], "error": None}

    async def list_rules(params):
        state["params"].append(params)
        if state["error"]:
            raise state["error"]
        ids = params.get("rule_ids")
        items = [RULES[i] for i in ids.split(",")] if ids else list(RULES.values())
        return items, len(items)

    monkeypatch.setattr(settings, "wazuh_api_url", "https://wazuh.invalid:55000")
    monkeypatch.setattr(settings, "wazuh_api_user", "siemantics")
    monkeypatch.setattr(settings, "wazuh_api_password", "x")
    monkeypatch.setattr(wazuh_client, "list_rules", list_rules)
    return state


def brute(alert_id, level=10):
    payload = wazuh_alert(alert_id=alert_id, level=level, description="sshd: brute force", data={"srcip": "45.155.205.233"})
    payload["rule"]["id"] = "5763"
    return payload


def test_seen_only_lists_rules_with_siemantics_statistics(logged_in, iris, wazuh):
    first = process_alert(logged_in, brute("b1", level=13))
    process_alert(logged_in, brute("b2", level=13))
    process_alert(logged_in, wazuh_alert(alert_id="t1", level=2, data={"srcip": "203.0.113.9"}))
    logged_in.patch(f"/api/v1/alerts/{first['display_id']}/label", json={"ground_truth": "true_positive"})

    body = logged_in.get("/api/v1/wazuh/rules?search=sshd&level_min=5").json()
    params = wazuh["params"][-1]
    assert params["rule_ids"] == "100,5763" and params["search"] == "sshd" and params["level"] == "5-16"
    rules = {r["id"]: r for r in body["items"]}
    assert set(rules) == {100, 5763}
    stats = rules[5763]["siemantics"]
    assert stats["alerts"] == 2 and stats["escalated"] == 2 and stats["true_positive"] == 1
    assert rules[5763]["compliance"] == {"pci_dss": ["11.4"]} and rules[5763]["details"]["frequency"] == "8"


def test_all_rules_mode_and_empty_siemantics(logged_in, wazuh):
    assert logged_in.get("/api/v1/wazuh/rules").json() == {"total": 0, "items": [], "stats_days": 30}
    assert wazuh["params"] == []
    body = logged_in.get("/api/v1/wazuh/rules?seen_only=false&sort=-level").json()
    assert body["total"] == 3 and wazuh["params"][-1]["sort"] == "-level"
    assert all(r["siemantics"] is None for r in body["items"])


def test_missing_rules_permission_is_explained(logged_in, wazuh):
    wazuh["error"] = WazuhApiError("forbidden", 403)
    res = logged_in.get("/api/v1/wazuh/rules?seen_only=false")
    assert res.status_code == 403 and "rules:read" in res.json()["detail"]


def test_rules_need_l2_and_configuration(logged_in, monkeypatch):
    assert logged_in.get("/api/v1/wazuh/rules?seen_only=false").status_code == 503
    logged_in.post("/api/v1/users", json={"username": "alice", "password": "analyst-pass", "role": "analyst"})
    alice = TestClient(app)
    alice.post("/api/v1/auth/login", json={"username": "alice", "password": "analyst-pass"})
    assert alice.get("/api/v1/wazuh/rules").status_code == 403
