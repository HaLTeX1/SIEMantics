import time

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app

from conftest import process_alert, wazuh_alert
from test_response import wazuh  # noqa: F401


@pytest.fixture(autouse=True)
def manager_ip(monkeypatch):
    # A teszt Wazuh API hostnevvel van megadva, ezert a manager IP-jet itt adjuk meg.
    monkeypatch.setattr(settings, "response_isolation_allow", "10.64.0.82")


def alert(client, agent_id="001", alert_id="i1"):
    names = {"001": "web01", "015": "HL-AD-CORE01", "009": "UL_RL_WRKS_W11", "000": "lab-soc-siem01"}
    return process_alert(client, wazuh_alert(alert_id=alert_id, level=13, agent={"id": agent_id, "name": names[agent_id]},
                                             data={"srcip": "45.155.205.10"}))


def isolate(client, record, name="web01", hours=24):
    return client.post(f"/api/v1/alerts/{record['display_id']}/isolate",
                       json={"duration_hours": hours, "confirm_hostname": name})


def test_isolate_linux_host_keeps_the_manager_reachable(logged_in, iris, wazuh):  # noqa: F811
    record = alert(logged_in)
    res = isolate(logged_in, record, name="WEB01")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["action"] == "isolate_host" and body["status"] == "sent" and body["duration_seconds"] == 86400
    assert wazuh.commands[-1][:2] == ("siemantics-isolate86400", ["001"])
    args = wazuh.arguments[-1]
    assert args[:2] == ["isolate", "10.64.0.82"] and args[2].startswith("until=")
    assert abs(int(args[2][6:]) - (time.time() + 86400)) < 60
    assert "Host isolated: web01" in iris.notes[-1][2][0][0]


def test_windows_host_and_release(logged_in, iris, wazuh, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "response_isolation_allow", "10.64.0.82, nope, ::1")
    record = alert(logged_in, agent_id="015")
    assert isolate(logged_in, record, name="HL-AD-CORE01", hours=1).status_code == 200
    assert wazuh.commands[-1][0] == "win-siemantics-isolate3600"
    assert wazuh.arguments[-1][:2] == ["isolate", "10.64.0.82"]

    res = logged_in.post(f"/api/v1/alerts/{record['display_id']}/release")
    assert res.status_code == 200 and res.json()["action"] == "release_host"
    assert wazuh.commands[-1][0] == "win-siemantics-isolate0" and wazuh.arguments[-1] == ["release"]
    history = logged_in.get(f"/api/v1/alerts/{record['display_id']}/responses").json()
    assert [h["action"] for h in history] == ["release_host", "isolate_host"]


@pytest.mark.parametrize("agent_id,name,protected,status_code,text", [
    ("001", "web02", "", 422, "type the host name"),
    ("000", "lab-soc-siem01", "", 422, "no own agent"),
    ("001", "web01", "web01, iris", 422, "protected host"),
    ("009", "UL_RL_WRKS_W11", "", 409, "not active"),
])
def test_isolation_guards(logged_in, iris, wazuh, monkeypatch, agent_id, name, protected, status_code, text):  # noqa: F811
    monkeypatch.setattr(settings, "response_protected_hosts", protected)
    record = alert(logged_in, agent_id=agent_id)
    res = isolate(logged_in, record, name=name)
    assert res.status_code == status_code and text in res.json()["detail"]
    assert wazuh.commands == []


def test_no_reachable_address_means_no_isolation(logged_in, iris, wazuh, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "response_isolation_allow", "")
    monkeypatch.setattr(settings, "wazuh_api_url", "https://wazuh.lab:55000")
    record = alert(logged_in)
    res = isolate(logged_in, record)
    assert res.status_code == 503 and "RESPONSE_ISOLATION_ALLOW" in res.json()["detail"]


def test_only_l2_and_admin_can_isolate(logged_in, iris, wazuh):  # noqa: F811
    record = alert(logged_in)
    logged_in.post("/api/v1/users", json={"username": "carol", "password": "analyst-pass", "role": "analyst",
                                          "response_allowed": True})
    carol = TestClient(app)
    carol.post("/api/v1/auth/login", json={"username": "carol", "password": "analyst-pass"})
    # IP blokkolasra engedelyezett analyst sem izolalhat.
    assert carol.get("/api/v1/auth/me").json()["can_isolate"] is False
    assert isolate(carol, record).status_code == 403
    assert carol.post(f"/api/v1/alerts/{record['display_id']}/release").status_code == 403


def test_manager_ip_comes_from_the_wazuh_api_url(monkeypatch):
    from app.response import isolation_allowlist

    monkeypatch.setattr(settings, "response_isolation_allow", "10.64.0.127")
    monkeypatch.setattr(settings, "wazuh_api_url", "https://10.64.0.82:55000")
    assert isolation_allowlist() == ["10.64.0.127", "10.64.0.82"]
