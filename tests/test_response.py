import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.response import ResponseError, validate_ip
from app.wazuh_client import wazuh_client

from conftest import process_alert, wazuh_alert

AGENTS = {
    "001": {"id": "001", "name": "web01", "status": "active", "os": {"platform": "ubuntu"}},
    "015": {"id": "015", "name": "HL-AD-CORE01", "status": "active", "os": {"platform": "windows"}},
    "009": {"id": "009", "name": "UL_RL_WRKS_W11", "status": "disconnected", "os": {"platform": "windows"}},
}


class FakeWazuh:
    def __init__(self) -> None:
        self.commands: list[tuple[str, list[str], dict]] = []
        self.fail_agents: set[str] = set()

    async def get_agents(self, agent_ids=None, *, active_only=False):
        agents = [AGENTS[a] for a in agent_ids if a in AGENTS] if agent_ids else list(AGENTS.values())
        return [a for a in agents if a["status"] == "active"] if active_only else agents

    async def run_command(self, command, agent_ids, alert):
        self.commands.append((command, agent_ids, alert))
        ok = [a for a in agent_ids if a not in self.fail_agents]
        return ok, {a: "agent unreachable" for a in agent_ids if a in self.fail_agents}


@pytest.fixture
def wazuh(monkeypatch) -> FakeWazuh:
    fake = FakeWazuh()
    monkeypatch.setattr(settings, "wazuh_api_url", "https://wazuh.invalid:55000")
    monkeypatch.setattr(settings, "wazuh_api_user", "siemantics")
    monkeypatch.setattr(settings, "wazuh_api_password", "x")
    monkeypatch.setattr(settings, "response_protected_networks", "8.8.8.0/24, not-an-ip")
    monkeypatch.setattr(wazuh_client, "get_agents", fake.get_agents)
    monkeypatch.setattr(wazuh_client, "run_command", fake.run_command)
    return fake


def alert(client, agent_id="001", level=13, alert_id="b1"):
    agent = {"id": agent_id, "name": AGENTS.get(agent_id, {}).get("name", "manager")}
    return process_alert(client, wazuh_alert(alert_id=alert_id, level=level, agent=agent,
                                             data={"srcip": "45.155.205.10"}))


def block(client, display_id, **body):
    return client.post(f"/api/v1/alerts/{display_id}/block-ip", json={"ip": "45.155.205.10", **body})


# --- validalas

@pytest.mark.parametrize("ip", ["10.64.0.5", "127.0.0.1", "192.168.1.1", "169.254.1.1", "::1", "fd00::1", "nope"])
def test_non_public_addresses_are_rejected(ip):
    with pytest.raises(ResponseError):
        validate_ip(ip)


def test_protected_networks_are_rejected(wazuh):
    with pytest.raises(ResponseError, match="protected"):
        validate_ip("8.8.8.8")
    assert validate_ip(" 1.1.1.1 ") == "1.1.1.1"


# --- blokkolas

def test_block_on_the_alert_agent_with_iris_note(logged_in, iris, wazuh):
    record = alert(logged_in)
    res = block(logged_in, record["display_id"], duration_hours=1)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "sent" and body["scope"] == "agent" and body["duration_seconds"] == 3600
    assert body["requested_by"]["username"] == "admin" and body["iris_noted"] is True
    assert wazuh.commands == [("firewall-drop3600", ["001"], {"data": {"srcip": "45.155.205.10"}})]
    note = iris.notes[-1]
    assert note[0] == record["iris_case_id"] and "45.155.205.10" in note[2][0][0]
    assert logged_in.get(f"/api/v1/alerts/{record['display_id']}/responses").json()[0]["id"] == body["id"]


def test_block_on_all_agents_uses_the_os_specific_command(logged_in, iris, wazuh):
    record = alert(logged_in)
    body = block(logged_in, record["display_id"], scope="all", duration_hours=168).json()
    assert sorted(wazuh.commands, key=lambda c: c[0]) == [
        ("firewall-drop604800", ["001"], {"data": {"srcip": "45.155.205.10"}}),
        ("netsh604800", ["015"], {"data": {"srcip": "45.155.205.10"}}),
    ]
    # A nem aktiv agent kimarad.
    assert {t["name"] for t in body["targets"]} == {"web01", "HL-AD-CORE01"}


def test_partial_failure_is_reported(logged_in, iris, wazuh):
    wazuh.fail_agents = {"015"}
    record = alert(logged_in)
    body = block(logged_in, record["display_id"], scope="all").json()
    assert body["status"] == "partial" and "HL-AD-CORE01: agent unreachable" in body["error_detail"]


def test_manager_alert_needs_all_agents_scope(logged_in, iris, wazuh):
    record = alert(logged_in, agent_id="000")
    res = block(logged_in, record["display_id"])
    assert res.status_code == 422 and "all agents" in res.json()["detail"]
    assert wazuh.commands == []


def test_inactive_agent_is_rejected(logged_in, iris, wazuh):
    record = alert(logged_in, agent_id="009")
    assert block(logged_in, record["display_id"]).status_code == 409


def test_private_ip_is_never_sent(logged_in, iris, wazuh):
    record = alert(logged_in)
    res = logged_in.post(f"/api/v1/alerts/{record['display_id']}/block-ip", json={"ip": "10.64.0.83"})
    assert res.status_code == 422 and wazuh.commands == []


def test_disabled_without_configuration(logged_in, iris):
    record = alert(logged_in)
    assert block(logged_in, record["display_id"]).status_code == 503
    assert logged_in.get("/api/v1/config").json()["response_enabled"] is False


def test_analyst_without_permission_cannot_block(logged_in, iris, wazuh):
    record = alert(logged_in)
    logged_in.post("/api/v1/users", json={"username": "alice", "password": "analyst-pass", "role": "analyst"})
    alice = TestClient(app)
    alice.post("/api/v1/auth/login", json={"username": "alice", "password": "analyst-pass"})
    assert block(alice, record["display_id"]).status_code == 403
    assert alice.get(f"/api/v1/alerts/{record['display_id']}/responses").status_code == 200
