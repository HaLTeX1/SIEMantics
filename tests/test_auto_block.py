import pytest

from app import auto_block, status
from app.config import settings

from conftest import process_alert, wazuh_alert
from test_response import AGENTS, wazuh  # noqa: F401

ATTACKER = "45.155.205.10"


@pytest.fixture
def abuse(monkeypatch):
    scores = {"value": 95}

    async def score(record, ip):
        return scores["value"]

    monkeypatch.setattr(auto_block, "_abuse_score", score)
    return scores


def brute(alert_id, ip=ATTACKER, agent_id="001", groups=("syslog", "sshd", "authentication_failures")):
    agent = {"id": agent_id, "name": AGENTS.get(agent_id, {}).get("name", "lab-soc-siem01")}
    payload = wazuh_alert(alert_id=alert_id, level=10, agent=agent, data={"srcip": ip},
                          description="sshd: brute force trying to get access to the system.")
    payload["rule"].update(id="5763", groups=list(groups))
    return payload


def actions(client, record):
    return client.get(f"/api/v1/alerts/{record['display_id']}/responses").json()


def test_dry_run_is_the_default_and_sends_nothing(logged_in, iris, wazuh, abuse):  # noqa: F811
    record = process_alert(logged_in, brute("a1"))
    [action] = actions(logged_in, record)
    assert action["status"] == "dry_run" and action["automatic"] is True and action["requested_by"] is None
    assert wazuh.commands == [] and action["targets"][0]["command"] == "firewall-drop3600"
    assert "would block" in status.snapshot("auto_block")["last_result"]["decision"]


def test_enforce_blocks_and_notes_the_case(logged_in, iris, wazuh, abuse, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "auto_block_mode", "enforce")
    record = process_alert(logged_in, brute("a2"))
    [action] = actions(logged_in, record)
    assert action["status"] == "sent" and action["iris_noted"] is True
    assert wazuh.commands == [("firewall-drop3600", ["001"], {"data": {"srcip": ATTACKER}})]
    assert "automatically by SIEMantics" in iris.notes[-1][2][0][1]


@pytest.mark.parametrize("change,reason", [
    ({"score": 50}, "AbuseIPDB score 50 < 90"),
    ({"groups": ("syslog", "sshd")}, "rule group not selected"),
    ({"ip": "10.64.0.50"}, "not a public address"),
    ({"agent_id": "000"}, "AUTO_BLOCK_SCOPE=all"),
])
def test_conditions_are_required(logged_in, iris, wazuh, abuse, change, reason):  # noqa: F811
    abuse["value"] = change.get("score", 95)
    kwargs = {k: v for k, v in change.items() if k != "score"}
    record = process_alert(logged_in, brute("c1", **kwargs))
    assert actions(logged_in, record) == []
    assert reason in status.snapshot("auto_block")["last_result"]["decision"]


def test_same_ip_is_not_blocked_twice_and_hourly_limit(logged_in, iris, wazuh, abuse, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "auto_block_mode", "enforce")
    monkeypatch.setattr(settings, "auto_block_max_per_hour", 2)
    process_alert(logged_in, brute("d1"))
    process_alert(logged_in, brute("d2", ip=ATTACKER, groups=("sshd", "authentication_failures", "x")))
    assert len(wazuh.commands) == 1
    assert "already blocked" in status.snapshot("auto_block")["last_result"]["decision"]
    process_alert(logged_in, brute("d3", ip="45.155.205.11"))
    process_alert(logged_in, brute("d4", ip="45.155.205.12"))
    assert len(wazuh.commands) == 2
    assert "hourly limit" in status.snapshot("auto_block")["last_result"]["decision"]


def test_manager_alert_blocks_everywhere_with_scope_all(logged_in, iris, wazuh, abuse, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "auto_block_mode", "enforce")
    monkeypatch.setattr(settings, "auto_block_scope", "all")
    process_alert(logged_in, brute("m1", agent_id="000"))
    assert {c[0] for c in wazuh.commands} == {"firewall-drop3600", "netsh3600"}


def test_off_mode_does_nothing(logged_in, iris, wazuh, abuse, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "auto_block_mode", "off")
    record = process_alert(logged_in, brute("o1"))
    assert actions(logged_in, record) == [] and status.snapshot("auto_block") == {}


def test_switching_to_enforce_blocks_an_ip_seen_in_dry_run(logged_in, iris, wazuh, abuse, monkeypatch):  # noqa: F811
    process_alert(logged_in, brute("s1"))
    assert wazuh.commands == []
    monkeypatch.setattr(settings, "auto_block_mode", "enforce")
    process_alert(logged_in, brute("s2"))
    assert len(wazuh.commands) == 1


def test_settings_accept_env_strings(monkeypatch):
    # A .env minden erteke szoveg: az app ezzel is induljon el (a deploy health check ezen bukott el).
    from app.config import Settings

    monkeypatch.setenv("AUTO_BLOCK_DURATION_HOURS", "24")
    monkeypatch.setenv("AUTO_BLOCK_MODE", "enforce")
    monkeypatch.setenv("AUTO_BLOCK_SCOPE", "all")
    monkeypatch.setenv("AUTO_BLOCK_MAX_PER_HOUR", "5")
    loaded = Settings()
    assert (loaded.auto_block_duration_hours, loaded.auto_block_mode, loaded.auto_block_scope) == (24, "enforce", "all")
    monkeypatch.setenv("AUTO_BLOCK_DURATION_HOURS", "5")
    with pytest.raises(ValueError):
        Settings()
