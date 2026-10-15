from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app import pipeline
from app.config import settings
from app.db import async_session
from app.hosts import _ports_summary, ip_context
from app.llm_engine import LlmUnavailable
from app.main import app
from app.models import AlertRecord
from app.wazuh_client import wazuh_client

from conftest import WEBHOOK_HEADERS, process_alert, wazuh_alert

AGENTS = [
    {"id": "013", "name": "zabbix", "status": "active", "ip": "10.64.0.40", "group": ["default", "linux"],
     "os": {"name": "Ubuntu", "version": "24.04 LTS", "platform": "ubuntu"}, "version": "v4.14.5"},
    {"id": "009", "name": "UL_RL_WRKS_W11", "status": "disconnected", "ip": "any",
     "os": {"name": "Microsoft Windows 11 Pro", "platform": "windows"}},
]
PORTS = [
    {"protocol": "tcp", "state": "listening", "local": {"ip": "0.0.0.0", "port": 10051}, "process": "zabbix_server"},
    {"protocol": "tcp6", "state": "listening", "local": {"ip": "::", "port": 22}, "process": "sshd"},
    {"protocol": "tcp", "state": "established", "local": {"ip": "10.64.0.40", "port": 51515}, "process": "x"},
    {"protocol": "udp", "local": {"ip": "0.0.0.0", "port": 161}, "process": "snmpd"},
]


@pytest.fixture
def wazuh(monkeypatch):
    state = {"agents": list(AGENTS)}

    async def agents():
        return state["agents"]

    async def ports(agent_id):
        return PORTS

    monkeypatch.setattr(settings, "wazuh_api_url", "https://wazuh.invalid:55000")
    monkeypatch.setattr(settings, "wazuh_api_user", "siemantics")
    monkeypatch.setattr(settings, "wazuh_api_password", "x")
    monkeypatch.setattr(wazuh_client, "list_agents_detailed", agents)
    monkeypatch.setattr(wazuh_client, "listening_ports", ports)
    return state


@pytest.fixture
def seen(monkeypatch) -> list:
    # A triazs hivas teljes kontextusa (kapcsolodo, kornyezet, elozmenyek), majd a valodi motor.
    calls: list = []
    real = pipeline.triage_alert

    async def spy(alert, related=None, environment=None, history=None):
        calls.append({"alert": alert, "related": related or [], "environment": environment or {},
                      "history": history or []})
        return await real(alert, related, environment, history)

    monkeypatch.setattr(pipeline, "triage_alert", spy)
    return calls


def user_client(admin, username, role):
    admin.post("/api/v1/users", json={"username": username, "password": "analyst-pass", "role": role})
    c = TestClient(app)
    c.post("/api/v1/auth/login", json={"username": username, "password": "analyst-pass"})
    return c


# --- host szinkron es kontextus

def test_ports_summary_keeps_listening_services():
    assert _ports_summary(PORTS) == ["tcp/22 sshd", "udp/161 snmpd", "tcp/10051 zabbix_server"]


def test_host_sync_keeps_manual_fields_and_flags_removed_hosts(logged_in, wazuh):
    assert logged_in.post("/api/v1/hosts/sync").json() == {"hosts": 2, "created": 2, "removed": 0}
    hosts = {h["agent_name"]: h for h in logged_in.get("/api/v1/hosts").json()}
    zabbix = hosts["zabbix"]
    assert zabbix["wazuh"]["os"] == "Ubuntu 24.04 LTS" and "tcp/10051 zabbix_server" in zabbix["wazuh"]["listening_ports"]
    # Nem aktiv agentnel nincs portlekeres.
    assert "listening_ports" not in hosts["UL_RL_WRKS_W11"]["wazuh"]

    logged_in.patch(f"/api/v1/hosts/{zabbix['id']}", json={"role": "Zabbix monitoring server", "criticality": "high"})
    wazuh["agents"] = AGENTS[:1]
    assert logged_in.post("/api/v1/hosts/sync").json() == {"hosts": 1, "created": 0, "removed": 1}
    hosts = {h["agent_name"]: h for h in logged_in.get("/api/v1/hosts").json()}
    assert hosts["zabbix"]["role"] == "Zabbix monitoring server" and hosts["zabbix"]["updated_by"]["username"] == "admin"
    assert hosts["UL_RL_WRKS_W11"]["in_wazuh"] is False
    assert logged_in.delete(f"/api/v1/hosts/{hosts['zabbix']['id']}").status_code == 409
    assert logged_in.delete(f"/api/v1/hosts/{hosts['UL_RL_WRKS_W11']['id']}").status_code == 200


def test_ip_context_uses_the_most_specific_known_network(logged_in):
    logged_in.post("/api/v1/networks", json={"cidr": "10.64.0.0/16", "label": "Lab network"})
    logged_in.post("/api/v1/networks", json={"cidr": "10.64.0.95", "label": "Forgejo git server"})
    assert logged_in.post("/api/v1/networks", json={"cidr": "nope", "label": "x"}).status_code == 422

    async def check():
        async with async_session() as session:
            return [await ip_context(session, ip) for ip in ("10.64.0.95", "10.64.0.7", "192.168.5.5", "45.155.205.10")]

    forgejo, lab, private, public = logged_in.portal.call(check)
    assert forgejo["known_as"] == "Forgejo git server" and forgejo["network"] == "10.64.0.95/32"
    assert lab["known_as"] == "Lab network" and lab["trusted"] is True
    assert private["scope"].startswith("private") and public["scope"] == "public"


def test_triage_gets_environment_and_analyst_history(logged_in, iris, wazuh, seen):
    logged_in.post("/api/v1/hosts/sync")
    zabbix = next(h for h in logged_in.get("/api/v1/hosts").json() if h["agent_name"] == "zabbix")
    logged_in.patch(f"/api/v1/hosts/{zabbix['id']}", json={"role": "monitoring server"})
    logged_in.post("/api/v1/networks", json={"cidr": "10.64.0.150", "label": "Zabbix frontend", "trusted": True})

    agent = {"id": "013", "name": "zabbix"}
    first = process_alert(logged_in, wazuh_alert("h1", agent=agent, data={"srcip": "10.64.0.150"}))
    logged_in.patch(f"/api/v1/alerts/{first['display_id']}/label", json={"ground_truth": "false_positive"})
    process_alert(logged_in, wazuh_alert("h2", agent=agent, data={"srcip": "10.64.0.150"}, full_log="other"))

    call = seen[-1]
    assert call["environment"]["host"]["role"] == "monitoring server"
    assert call["environment"]["host"]["os"] == "Ubuntu 24.04 LTS"
    assert call["environment"]["source_ip"]["known_as"] == "Zabbix frontend"
    assert call["history"][0]["display_id"] == first["display_id"]
    assert call["history"][0]["analyst_verdict"] == "false_positive" and call["history"][0]["same_host"] is True
    related = call["related"][0]
    assert related.analyst_verdict == "false_positive"


def test_environment_editing_needs_l2(logged_in, wazuh):
    analyst = user_client(logged_in, "alice", "analyst")
    l2 = user_client(logged_in, "bob", "l2")
    assert analyst.post("/api/v1/networks", json={"cidr": "10.0.0.1", "label": "x"}).status_code == 403
    assert analyst.post("/api/v1/hosts/sync").status_code == 403
    assert analyst.get("/api/v1/hosts").status_code == 200
    assert l2.post("/api/v1/networks", json={"cidr": "10.0.0.1", "label": "x"}).status_code == 201
    assert l2.post("/api/v1/hosts", json={"agent_name": "fw01", "role": "edge firewall"}).status_code == 201
    assert l2.get("/api/v1/auth/me").json()["can_edit_context"] is True


# --- kontextus esemenyek

def test_package_manager_events_are_context_only(logged_in, iris, seen):
    dpkg = wazuh_alert("pkg-1", level=7, description="New dpkg package installed.",
                       agent={"id": "013", "name": "zabbix"}, data={}, full_log="status installed avahi-daemon")
    dpkg["rule"].update(id="2902", groups=["syslog", "dpkg", "config_changed"])
    res = logged_in.post("/api/v1/alerts", json=dpkg, headers=WEBHOOK_HEADERS).json()
    assert res["status"] == "context"
    record = logged_in.get(f"/api/v1/alerts/{res['id']}").json()
    assert record["status"] == "suppressed" and record["triage_engine"] == "context"

    fim = wazuh_alert("fim-1", level=8, description="FIM: account database changed: /etc/passwd",
                      agent={"id": "013", "name": "zabbix"}, data={})
    process_alert(logged_in, fim)
    assert [r.display_id for r in seen[-1]["related"]] == [res["id"]]
    # A kontextus esemeny nem predikcio.
    assert logged_in.get("/api/v1/metrics").json()["by_engine"].get("context") is None


# --- LLM kieses

@pytest.fixture
def llm_down(monkeypatch):
    state = {"quota": False, "calls": 0}

    async def down(alert, *args):
        state["calls"] += 1
        raise LlmUnavailable("429 rate limit", quota=state["quota"])

    later: list = []
    monkeypatch.setattr(pipeline, "triage_alert", down)
    monkeypatch.setattr(pipeline.alert_queue, "enqueue_later", lambda record_id, delay: later.append((record_id, delay)))
    state["later"] = later
    return state


def test_llm_outage_keeps_the_alert_queued_instead_of_guessing(logged_in, iris, llm_down):
    res = logged_in.post("/api/v1/alerts", json=wazuh_alert("o1", level=8), headers=WEBHOOK_HEADERS).json()
    logged_in.portal.call(pipeline.alert_queue.join)
    record = logged_in.get(f"/api/v1/alerts/{res['id']}").json()
    assert record["status"] == "queued" and iris.calls == []
    assert record["error_detail"].startswith("waiting for the LLM")
    assert llm_down["later"] == [(res["record_id"], pipeline.RETRY_DELAY_SECONDS)]


def test_high_level_alert_goes_to_review_at_once_during_outage(logged_in, iris, llm_down):
    # Kritikus riasztas nem varhat orakig: azonnal elemzohoz kerul, es keziel eszkalalhato.
    res = logged_in.post("/api/v1/alerts", json=wazuh_alert("o2", level=13), headers=WEBHOOK_HEADERS).json()
    logged_in.portal.call(pipeline.alert_queue.join)
    record = logged_in.get(f"/api/v1/alerts/{res['id']}").json()
    assert record["status"] == "needs_review" and "needs manual triage now" in record["review_reason"]
    assert llm_down["later"] == []
    assert logged_in.post(f"/api/v1/alerts/{res['id']}/escalate").status_code == 200


def test_quota_error_pauses_the_queue(logged_in, iris, llm_down):
    llm_down["quota"] = True
    try:
        logged_in.post("/api/v1/alerts", json=wazuh_alert("q1", level=5), headers=WEBHOOK_HEADERS)
        logged_in.portal.call(pipeline.alert_queue.join)
        assert pipeline.alert_queue.pause_remaining() > 0
        # Szunet alatt a kovetkezo riasztas mar LLM hivas nelkul kerul vissza.
        logged_in.post("/api/v1/alerts", json=wazuh_alert("q2", level=5, full_log="x"), headers=WEBHOOK_HEADERS)
        logged_in.portal.call(pipeline.alert_queue.join)
        assert llm_down["calls"] == 1 and len(llm_down["later"]) == 2
    finally:
        pipeline.alert_queue._paused_until = 0.0


def test_alert_waiting_too_long_goes_to_manual_review(logged_in, iris, llm_down):
    async def old_record() -> int:
        async with async_session() as session:
            record = AlertRecord(alert_id="old", rule_description="r", severity=5, status=pipeline.AlertStatus.QUEUED,
                                 processing_time_ms=0.0, raw_payload=wazuh_alert("old", level=5),
                                 received_at=datetime.utcnow() - timedelta(hours=settings.llm_retry_max_hours + 1))
            session.add(record)
            await session.commit()
            return record.id

    record_id = logged_in.portal.call(old_record)
    pipeline.alert_queue.enqueue(record_id)
    logged_in.portal.call(pipeline.alert_queue.join)
    record = logged_in.get(f"/api/v1/alerts/ID-{record_id}").json()
    assert record["status"] == "needs_review" and "LLM unavailable" in record["review_reason"]
    # Nem rendszer-dontes, a metrikak nem szamoljak.
    assert record["auto_status"] == "error"


def test_wait_mode_reports_llm_outage(logged_in, iris, llm_down):
    res = logged_in.post("/api/v1/alerts?wait=true", json=wazuh_alert("w1", level=5), headers=WEBHOOK_HEADERS)
    assert res.status_code == 503 and len(llm_down["later"]) == 1


# --- visszajatszo meres

def test_replay_measures_without_touching_the_database(logged_in, iris, monkeypatch):
    from app import eval_replay
    from app.schemas import TriageResult

    first = process_alert(logged_in, wazuh_alert("r1", level=13))
    logged_in.patch(f"/api/v1/alerts/{first['display_id']}/label", json={"ground_truth": "false_positive"})

    async def benign(alert, *args):
        return TriageResult(is_true_positive=False, confidence=0.9, reasoning="package install",
                            engine="openrouter", model="m:free")

    monkeypatch.setattr(eval_replay, "triage_alert", benign)
    monkeypatch.setattr(eval_replay, "llm_configured", lambda: True)
    report = logged_in.portal.call(eval_replay.replay, None, 0, None)
    # Mock eszkalalt (FP) -> az uj itelet elnyom (TN); a 13-as szint miatt needs_review.
    assert report["before"]["FP"] == 1 and report["after"]["TN"] == 1
    assert report["alerts"][0]["after"]["status"] == "needs_review"
    assert logged_in.get(f"/api/v1/alerts/{first['display_id']}").json()["status"] == "escalated"
