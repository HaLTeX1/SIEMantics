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


# --- megfekezett brute force automatikus lezarasa

@pytest.fixture
def indexer(monkeypatch):
    from app.surrounding import indexer_client

    state = {"success": False, "queries": []}

    async def search(body):
        state["queries"].append(body)
        return [{"rule": {"id": "5715"}}] if state["success"] else []

    monkeypatch.setattr(settings, "wazuh_indexer_url", "https://10.64.0.82")
    monkeypatch.setattr(settings, "wazuh_indexer_user", "siemantics-ro")
    monkeypatch.setattr(settings, "wazuh_indexer_password", "x")
    monkeypatch.setattr(indexer_client, "search", search)
    return state


def decision():
    return status.snapshot("auto_block")["last_result"]["decision"]


def test_blocked_brute_force_case_is_closed_tpni(logged_in, iris, wazuh, abuse, indexer, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "auto_block_mode", "enforce")
    record = process_alert(logged_in, brute("ac1"))
    case_id = record["iris_case_id"]
    assert case_id in iris.closed and iris.outcomes[case_id] == 4
    assert "TPNI" in iris.annotations[case_id] and "auto-closed" in iris.tags[case_id]
    assert "closed as true positive without impact" in decision()
    # A sikeres belepes keresese: ugyanaz az IP, authentication_success.
    login_checks = [q for q in indexer["queries"]
                    if {"term": {"rule.groups": "authentication_success"}} in q["query"]["bool"]["filter"]]
    assert len(login_checks) == 1 and {"term": {"data.srcip": ATTACKER}} in login_checks[0]["query"]["bool"]["filter"]

    closed = logged_in.get(f"/api/v1/alerts/{record['display_id']}").json()
    assert closed["ground_truth"] == "true_positive" and closed["label_source"] == "auto"
    assert closed["is_closed"] is True and "TPNI" in closed["case_closure_note"]
    # Nem elemzoi itelet: nem metrika.
    assert logged_in.get("/api/v1/metrics").json()["labeled_size"] == 0


def test_auto_label_is_not_analyst_history(logged_in, iris, wazuh, abuse, indexer, monkeypatch):  # noqa: F811
    from app import pipeline

    monkeypatch.setattr(settings, "auto_block_mode", "enforce")
    process_alert(logged_in, brute("ah1"))
    seen = []
    real = pipeline.triage_alert

    async def spy(alert, related=None, environment=None, history=None, *args, **kwargs):
        seen.append((history or [], related or []))
        return await real(alert, related, environment, history, *args, **kwargs)

    monkeypatch.setattr(pipeline, "triage_alert", spy)
    process_alert(logged_in, brute("ah2", ip="45.155.205.99"))
    history, related = seen[-1]
    assert history == [] and all(r.analyst_verdict is None for r in related)


@pytest.mark.parametrize("setup,reason", [
    ("success", "successful login"),
    ("no_indexer", "cannot check for successful logins"),
])
def test_case_stays_open_when_impact_cannot_be_ruled_out(logged_in, iris, wazuh, abuse, indexer, monkeypatch,
                                                         setup, reason):  # noqa: F811
    monkeypatch.setattr(settings, "auto_block_mode", "enforce")
    if setup == "success":
        indexer["success"] = True
    else:
        monkeypatch.setattr(settings, "wazuh_indexer_url", "")
    record = process_alert(logged_in, brute("open1"))
    assert record["iris_case_id"] not in iris.closed and reason in decision()
    assert logged_in.get(f"/api/v1/alerts/{record['display_id']}").json()["ground_truth"] is None


def test_case_with_other_alerts_stays_open(logged_in, iris, wazuh, abuse, indexer, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "auto_block_mode", "enforce")
    # Egy nem brute force riasztas ugyanarrol az IP-rol: ugyanabba az esetbe korrelalodik.
    other = wazuh_alert(alert_id="x1", level=12, agent={"id": "001", "name": "web01"}, data={"srcip": ATTACKER},
                        description="Webshell upload")
    other["rule"].update(id="5763", groups=["web", "attack"])
    process_alert(logged_in, other)
    record = process_alert(logged_in, brute("mix1"))
    assert record["iris_case_id"] not in iris.closed and "other than brute force" in decision()


def test_dry_run_only_reports_the_closing(logged_in, iris, wazuh, abuse, indexer):  # noqa: F811
    record = process_alert(logged_in, brute("dr1"))
    assert record["iris_case_id"] not in iris.closed
    assert f"would close case #{record['iris_case_id']}" in decision()


def test_same_ip_is_blocked_again_on_another_host(logged_in, iris, wazuh, abuse, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "auto_block_mode", "enforce")
    process_alert(logged_in, brute("h1", agent_id="001"))
    process_alert(logged_in, brute("h2", agent_id="015"))
    assert [c[1] for c in wazuh.commands] == [["001"], ["015"]]


# --- regebbi nyitott esetek

def _age_case(client, case_id, hours):
    async def age():
        from datetime import datetime, timedelta
        from sqlalchemy import update
        from app.db import async_session
        from app.models import AlertRecord
        async with async_session() as session:
            await session.execute(update(AlertRecord).where(AlertRecord.iris_case_id == case_id)
                                  .values(received_at=datetime.utcnow() - timedelta(hours=hours)))
            await session.commit()
    client.portal.call(age)


def test_old_quiet_brute_force_case_is_listed_then_closed(logged_in, iris, wazuh, abuse, indexer, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "auto_block_mode", "off")
    old = process_alert(logged_in, brute("old1"))
    recent = process_alert(logged_in, brute("new1", ip="45.155.205.20", agent_id="015"))
    _age_case(logged_in, old["iris_case_id"], 30)

    preview = logged_in.get("/api/v1/system/auto-close").json()
    by_case = {i["case_id"]: i for i in preview["items"]}
    assert by_case[old["iris_case_id"]]["closable"] is True
    assert "not blocked" in by_case[recent["iris_case_id"]]["reason"]
    assert preview["closed"] == [] and old["iris_case_id"] not in iris.closed

    run = logged_in.post("/api/v1/system/auto-close/run").json()
    assert run["closed"] == [old["iris_case_id"]] and iris.outcomes[old["iris_case_id"]] == 4
    assert "stopped 30 h ago" in iris.annotations[old["iris_case_id"]]
    record = logged_in.get(f"/api/v1/alerts/{old['display_id']}").json()
    assert record["label_source"] == "auto" and record["is_closed"] is True
    assert recent["iris_case_id"] not in iris.closed


def test_assigned_or_succeeded_cases_are_not_closed(logged_in, iris, wazuh, abuse, indexer, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "auto_block_mode", "off")
    taken = process_alert(logged_in, brute("t1"))
    _age_case(logged_in, taken["iris_case_id"], 30)
    me = logged_in.get("/api/v1/auth/me").json()
    logged_in.put(f"/api/v1/cases/{taken['iris_case_id']}/assignee", json={"user_id": me["id"]})
    reason = {i["case_id"]: i["reason"] for i in logged_in.get("/api/v1/system/auto-close").json()["items"]}
    assert reason[taken["iris_case_id"]] == "the case has an assignee"

    logged_in.put(f"/api/v1/cases/{taken['iris_case_id']}/assignee", json={"user_id": None})
    indexer["success"] = True
    run = logged_in.post("/api/v1/system/auto-close/run").json()
    assert run["closed"] == [] and taken["iris_case_id"] not in iris.closed


def test_merged_away_case_gets_a_closure_annotation(logged_in, iris):
    from test_case_actions import alert as case_alert

    first = process_alert(logged_in, case_alert("m1", host="h1", srcip="198.51.100.1", rule_id="101"))
    second = process_alert(logged_in, case_alert("m2", host="h2", srcip="198.51.100.2", rule_id="102"))
    logged_in.post("/api/v1/cases/merge", json={"alert_refs": [first["display_id"], second["display_id"]]})
    assert iris.annotations[second["iris_case_id"]].startswith(f"Merged into #{first['iris_case_id']} by admin")
