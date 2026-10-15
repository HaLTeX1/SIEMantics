from datetime import datetime, timezone

import pytest

from app import pipeline, status
from app.config import settings
from app.llm_engine import build_user_prompt
from app.schemas import NormalizedAlert
from app.surrounding import alert_time, indexer_client

from conftest import process_alert, wazuh_alert

EVENTS_BEFORE = [  # az indexer csokkeno sorrendben adja (legkozelebbi elol)
    {"timestamp": "2026-10-15T09:12:02.000+0200", "id": "e2", "rule": {"id": "5402", "level": 3, "description": "Successful sudo to ROOT executed.", "groups": ["sudo"]},
     "agent": {"name": "zabbix"}, "data": {"dstuser": "root"}, "full_log": "admin : TTY=pts/0 ; COMMAND=/usr/bin/apt install zabbix-agent2"},
    {"timestamp": "2026-10-15T09:10:40.000+0200", "id": "e1", "rule": {"id": "5715", "level": 3, "description": "sshd: authentication success.", "groups": ["sshd"]},
     "agent": {"name": "zabbix"}, "data": {"srcip": "10.64.0.150", "dstuser": "admin"}, "full_log": "Accepted publickey for admin from 10.64.0.150"},
]
EVENTS_AFTER = [
    {"timestamp": "2026-10-15T09:12:05.000+0200", "id": "e3", "rule": {"id": "2902", "level": 7, "description": "New dpkg package installed.", "groups": ["dpkg"]},
     "agent": {"name": "zabbix"}, "full_log": "status installed zabbix-agent2:amd64 " + "x" * 400},
]


@pytest.fixture
def indexer(monkeypatch):
    state = {"queries": [], "fail": False}

    async def search(body):
        state["queries"].append(body)
        if state["fail"]:
            raise RuntimeError("connection refused")
        order = body["sort"][0]["timestamp"]["order"]
        return EVENTS_BEFORE if order == "desc" else EVENTS_AFTER

    monkeypatch.setattr(settings, "wazuh_indexer_url", "https://wazuh.invalid:9200")
    monkeypatch.setattr(settings, "wazuh_indexer_user", "siemantics")
    monkeypatch.setattr(settings, "wazuh_indexer_password", "x")
    monkeypatch.setattr(indexer_client, "search", search)
    return state


@pytest.fixture
def seen(monkeypatch) -> list:
    calls: list = []
    real = pipeline.triage_alert

    async def spy(alert, related=None, environment=None, *args, **kwargs):
        calls.append(environment or {})
        return await real(alert, related, environment, *args, **kwargs)

    monkeypatch.setattr(pipeline, "triage_alert", spy)
    return calls


def user_alert(**extra):
    return wazuh_alert("own-1", level=8, description="New user added to the system.",
                       agent={"id": "013", "name": "zabbix"}, timestamp="2026-10-15T09:12:03.000+0200", **extra)


def test_alert_time_uses_the_wazuh_timestamp_in_utc():
    alert = NormalizedAlert(alert_id="a", rule_description="r", severity=3, log_snippet="",
                            timestamp="2026-10-15T09:12:03.120+0200")
    assert alert_time(alert) == datetime(2026, 10, 15, 7, 12, 3, 120000, tzinfo=timezone.utc)


def test_triage_sees_surrounding_events_in_time_order(logged_in, iris, indexer, seen):
    process_alert(logged_in, user_alert())
    events = seen[-1]["surrounding_events"]
    assert [e["rule_id"] for e in events] == ["5715", "5402", "2902"]
    assert events[0]["srcip"] == "10.64.0.150" and events[2]["log"].endswith("...") and len(events[2]["log"]) < 260

    before, after = indexer["queries"]
    assert before["query"]["bool"]["filter"][0] == {"term": {"agent.name": "zabbix"}}
    window = before["query"]["bool"]["filter"][1]["range"]["timestamp"]
    assert window == {"gte": "2026-10-15T07:02:03.000Z", "lte": "2026-10-15T07:12:03.000Z"}
    assert after["sort"] == [{"timestamp": {"order": "asc"}}]
    assert status.snapshot("indexer")["last_result"] == {"events": 3}


def test_prompt_puts_surrounding_events_at_top_level():
    alert = NormalizedAlert(alert_id="a", rule_description="r", severity=3, log_snippet="")
    prompt = build_user_prompt(alert, [], {"host": {"name": "zabbix"}, "surrounding_events": [{"rule_id": "2902"}]})
    assert '"surrounding_events": [\n    {\n      "rule_id": "2902"' in prompt
    assert '"environment": {\n    "host"' in prompt and prompt.count("surrounding_events") == 1


def test_manager_alerts_are_scoped_by_source_ip(logged_in, iris, indexer):
    manager = {"id": "000", "name": "lab-soc-siem01"}
    process_alert(logged_in, wazuh_alert("fw-1", level=5, agent=manager, data={"srcip": "45.155.205.233"}))
    assert indexer["queries"][0]["query"]["bool"]["filter"][0] == {"term": {"data.srcip": "45.155.205.233"}}


def test_indexer_outage_does_not_block_triage(logged_in, iris, indexer, seen):
    indexer["fail"] = True
    record = process_alert(logged_in, user_alert())
    assert record["status"] != "queued" and "surrounding_events" not in seen[-1]
    assert "refused" in status.snapshot("indexer")["last_error"]


def test_surrounding_api(logged_in, iris, indexer):
    record = process_alert(logged_in, user_alert(id="e2"))
    body = logged_in.get(f"/api/v1/alerts/{record['display_id']}/surrounding?minutes=15").json()
    assert body["enabled"] is True and body["window_minutes"] == 15
    # A riasztas sajat esemenye is benne van, megjelolve.
    assert [e["this_alert"] for e in body["events"]] == [False, True, False]

    indexer["fail"] = True
    assert logged_in.get(f"/api/v1/alerts/{record['display_id']}/surrounding").status_code == 502


def test_surrounding_api_when_not_configured(logged_in, iris):
    record = process_alert(logged_in, user_alert())
    assert logged_in.get(f"/api/v1/alerts/{record['display_id']}/surrounding").json() == {
        "enabled": False, "window_minutes": 15, "events": []}


@pytest.mark.parametrize("via_dashboard,expected_path,expected_params", [
    (False, "/wazuh-alerts-4.x-*/_search", {}),
    (True, "/api/console/proxy", {"path": "wazuh-alerts-4.x-*/_search", "method": "POST"}),
])
def test_indexer_request_route(monkeypatch, via_dashboard, expected_path, expected_params):
    # Kozvetlen indexer, vagy a Wazuh dashboard console proxyja (az indexer csak 127.0.0.1-en figyel).
    import asyncio

    import httpx

    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"hits": {"hits": [{"_source": {"id": "x"}}]}})

    monkeypatch.setattr(settings, "wazuh_indexer_url", "https://10.64.0.82")
    monkeypatch.setattr(settings, "wazuh_indexer_via_dashboard", via_dashboard)
    monkeypatch.setattr(indexer_client, "_client", lambda: httpx.AsyncClient(
        base_url="https://10.64.0.82", auth=("u", "p"), transport=httpx.MockTransport(handler)))

    hits = asyncio.run(indexer_client.search({"size": 1}))
    request = seen[0]
    assert hits == [{"id": "x"}] and request.method == "POST" and request.url.path == expected_path
    assert dict(request.url.params) == expected_params
    assert ("osd-xsrf" in request.headers) is via_dashboard
    assert request.headers["authorization"].startswith("Basic ")
