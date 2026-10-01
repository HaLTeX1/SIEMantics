import asyncio
import json

import httpx
import pytest

from app import iris_client as iris_module
from app.iris_report import (
    CaseContext,
    _code,
    _fence,
    case_description,
    case_name,
    case_notes,
    case_tags,
    event_time,
    ioc_description,
    ioc_type_name,
    mitre_url,
    timeline_category,
    timeline_content,
)
from app.normalize import normalize_wazuh_alert
from app.schemas import TriageResult, WazuhAlertPayload

SSH_BRUTE_FORCE = {
    "id": "1727791201.100001",
    "timestamp": "2026-10-01T14:20:01.512+0000",
    "rule": {
        "id": "5763",
        "level": 10,
        "description": "sshd: brute force trying to get access to the system. Authentication failed.",
        "groups": ["syslog", "sshd", "authentication_failures"],
        "firedtimes": 1,
        "frequency": 8,
        "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
        "pci_dss": ["10.2.4", "11.4"],
    },
    "agent": {"id": "003", "name": "lab-web01", "ip": "10.64.0.21"},
    "manager": {"name": "wazuh-manager"},
    "decoder": {"parent": "sshd", "name": "sshd"},
    "location": "/var/log/auth.log",
    "data": {"srcip": "185.220.101.45", "srcport": "51122", "dstuser": "root"},
    "full_log": "Oct  1 14:20:01 lab-web01 sshd[21877]: Failed password for root from 185.220.101.45 port 51122 ssh2",
}


def _ctx(raw=SSH_BRUTE_FORCE, recommended="medium", **kwargs) -> CaseContext:
    alert = normalize_wazuh_alert(WazuhAlertPayload.model_validate(raw))
    triage = TriageResult(
        is_true_positive=True,
        confidence=0.87,
        reasoning="Repeated failed root logins from a Tor exit node.",
        iocs=["185.220.101.45"],
        recommended_severity=recommended,
        engine="openrouter",
        model="some/model:free",
    )
    enrichment = [{
        "ioc": "185.220.101.45",
        "virustotal": {"malicious": 12, "suspicious": 1, "harmless": 50, "reputation": -20, "country": "DE", "as_owner": "Tor"},
        "abuseipdb": {"abuse_confidence_score": 100, "total_reports": 3000, "country_code": "DE", "isp": "Tor"},
    }]
    return CaseContext(display_id="ID-42", alert=alert, triage=triage, enrichment=enrichment, raw=raw, **kwargs)


def test_severity_never_below_wazuh_level():
    # Wazuh 10 = high, az LLM medium ajanlasa nem csokkentheti.
    ctx = _ctx(recommended="medium")
    assert ctx.severity == "high" and ctx.priority == "P2"
    assert _ctx(recommended="critical").priority == "P1"


def test_case_name_carries_id_priority_and_host():
    name = case_name(_ctx())
    assert name.startswith("[SIEMantics ID-42] [P2/HIGH] sshd: brute force")
    assert name.endswith("@ lab-web01")
    assert len(case_name(_ctx(raw={**SSH_BRUTE_FORCE, "rule": {**SSH_BRUTE_FORCE["rule"], "description": "x" * 400}}))) == 256


def test_case_description_has_key_facts_for_l2():
    desc = case_description(_ctx())
    for expected in ("ID-42", "P2 / HIGH", "`5763`", "[T1110](https://attack.mitre.org/techniques/T1110/)",
                     "`lab-web01`", "`185.220.101.45:51122`", "`root`", "`/var/log/auth.log`", "87%"):
        assert expected in desc


def test_notes_cover_triage_details_ti_checklist_and_evidence():
    notes = dict(case_notes(_ctx()))
    assert list(notes) == [
        "1. Triage summary", "2. Alert details", "3. Threat intelligence", "4. Investigation checklist", "5. Raw evidence",
    ]
    assert "`10.2.4`" in notes["2. Alert details"]  # compliance
    assert "12 malicious" in notes["3. Threat intelligence"]
    assert "100% confidence" in notes["3. Threat intelligence"]
    checklist = notes["4. Investigation checklist"]
    assert "successful login from the same source" in checklist  # MITRE taktika
    assert "Count failed attempts" in checklist  # Wazuh csoport
    assert "data.srcip:185.220.101.45" in checklist
    assert "Lead Analyst review required" in checklist
    assert json.dumps(SSH_BRUTE_FORCE["data"]["dstuser"]) in notes["5. Raw evidence"]


def test_manual_escalation_is_visible():
    ctx = _ctx(escalated_by="analyst1")
    assert "Manually escalated by analyst1" in case_description(ctx)
    assert "manual-escalation" in case_tags(ctx)


def test_works_without_raw_payload():
    ctx = _ctx()
    ctx.raw = {}
    notes = dict(case_notes(ctx))
    assert "not stored" in notes["5. Raw evidence"]
    assert case_name(ctx).startswith("[SIEMantics ID-42]")


def test_attacker_text_cannot_break_out_of_code():
    assert _code("a`b|c\nd") == "``a`b\\|c d``"
    fenced = _fence("```\n# heading\n```")
    assert fenced.startswith("````\n") and fenced.endswith("\n````")


def test_ioc_helpers():
    assert ioc_type_name("185.220.101.45") == "ip-any"
    assert ioc_type_name("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert ioc_type_name("a" * 64) == "sha256"
    assert ioc_type_name("evil.example.com") == "domain"
    assert ioc_type_name("https://evil.example.com/x") == "url"
    assert ioc_type_name("payload.exe -enc") == "other"
    assert mitre_url("T1059.001") == "https://attack.mitre.org/techniques/T1059/001/"
    desc = ioc_description(_ctx(), "185.220.101.45")
    assert "source IP" in desc and "ID-42" in desc and "12 malicious" in desc


def test_event_time_keeps_wazuh_timezone():
    assert event_time(_ctx()) == ("2026-10-01T14:20:01.512", "+00:00")
    cest = {**SSH_BRUTE_FORCE, "timestamp": "2026-10-01T16:20:01.512+0200"}
    assert event_time(_ctx(raw=cest)) == ("2026-10-01T16:20:01.512", "+02:00")
    negative = {**SSH_BRUTE_FORCE, "timestamp": "2026-10-01T09:20:01-0530"}
    assert event_time(_ctx(raw=negative)) == ("2026-10-01T09:20:01.000", "-05:30")


def test_event_time_falls_back_to_received_at():
    ctx = _ctx(raw={**SSH_BRUTE_FORCE, "timestamp": "not a date"})
    date, tz = event_time(ctx)
    assert tz == "+00:00"
    assert date == ctx.alert.received_at.isoformat(timespec="milliseconds")


def test_timeline_category_and_content():
    ctx = _ctx()
    assert timeline_category(ctx) == "Credential Access"
    no_mitre = {**SSH_BRUTE_FORCE, "rule": {k: v for k, v in SSH_BRUTE_FORCE["rule"].items() if k != "mitre"}}
    assert timeline_category(_ctx(raw=no_mitre)) == "Unspecified"
    content = timeline_content(ctx)
    assert "P2 / HIGH" in content and "`185.220.101.45:51122`" in content and "[T1110]" in content
    assert "manually escalated by analyst1" in timeline_content(_ctx(escalated_by="analyst1"))


class FakeIris:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict | None]] = []
        self.failing: set[str] = set()
        # Utvonal szerinti egyedi valasz adatok.
        self.responses: dict[str, object] = {}

    def by_path(self) -> dict[str, list]:
        out: dict[str, list] = {}
        for path, body in self.calls:
            out.setdefault(path, []).append(body)
        return out


@pytest.fixture
def fake_iris(monkeypatch) -> FakeIris:
    fake = FakeIris()
    lookups = {
        "/manage/ioc-types/list": [{"type_name": "ip-any", "type_id": 76}, {"type_name": "other", "type_id": 96}],
        "/manage/asset-type/list": [{"asset_name": "Linux - Server", "asset_id": 3}],
        "/manage/severities/list": [
            {"severity_name": "Medium", "severity_id": 4},
            {"severity_name": "High", "severity_id": 5},
            {"severity_name": "Critical", "severity_id": 6},
        ],
        "/manage/event-categories/list": [{"name": "Unspecified", "id": 1}, {"name": "Credential Access", "id": 8}],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        fake.calls.append((path, json.loads(request.content) if request.content else None))
        if path in fake.failing:
            return httpx.Response(400, json={"message": "rejected"})
        if path in fake.responses:
            return httpx.Response(200, json={"data": fake.responses[path]})
        if path in lookups:
            return httpx.Response(200, json={"data": lookups[path]})
        return httpx.Response(200, json={"data": {"case_id": 7, "group_id": 9, "ioc_id": 55, "asset_id": 31}})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        iris_module.httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw)
    )
    return fake


def _create_case():
    ctx = _ctx()
    return asyncio.run(iris_module.IrisClient().create_case_from_alert(
        ctx.alert, ctx.triage, ctx.enrichment, display_id="ID-42", raw_payload=SSH_BRUTE_FORCE
    ))


def test_iris_client_sends_full_case(fake_iris):
    assert _create_case().case_id == 7

    calls = fake_iris.by_path()
    assert calls["/manage/cases/add"][0]["case_name"].startswith("[SIEMantics ID-42]")
    assert calls["/case/notes/groups/add"][0]["group_title"] == "SIEMantics ID-42"
    assert len(calls["/case/notes/add"]) == 5
    ioc = calls["/case/ioc/add"][0]
    assert ioc["ioc_type_id"] == 76 and "ID-42" in ioc["ioc_tags"]
    assert calls["/manage/cases/update/7"][0]["severity_id"] == 5
    assert "T1110" in calls["/manage/cases/update/7"][0]["case_tags"]

    event = calls["/case/timeline/events/add"][0]
    assert event["event_date"] == "2026-10-01T14:20:01.512" and event["event_tz"] == "+00:00"
    assert event["event_category_id"] == 8
    # Az esemeny a letrehozott assethez es IoC-hoz kapcsolodik.
    assert event["event_assets"] == [31] and event["event_iocs"] == [55]
    assert event["event_raw"] == SSH_BRUTE_FORCE["full_log"]
    assert event["event_in_summary"] and event["event_in_graph"]


def test_iris_client_failures_after_case_creation_are_best_effort(fake_iris):
    fake_iris.failing = {"/case/assets/add", "/case/ioc/add"}
    assert _create_case().case_id == 7

    calls = fake_iris.by_path()
    event = calls["/case/timeline/events/add"][0]
    assert event["event_assets"] == [] and event["event_iocs"] == []
    assert "/manage/cases/update/7" in calls


def test_iris_client_timeline_failure_keeps_case(fake_iris):
    fake_iris.failing = {"/case/timeline/events/add"}
    assert _create_case().case_id == 7
    assert "/manage/cases/update/7" in fake_iris.by_path()


def _add_to_case():
    ctx = _ctx()
    return asyncio.run(iris_module.IrisClient().add_alert_to_case(
        7, ctx.alert, ctx.triage, ctx.enrichment,
        display_id="ID-43", correlated_with="ID-42", raw_payload=SSH_BRUTE_FORCE,
    ))


def _open_case(fake: FakeIris, **case):
    fake.responses.update({
        "/manage/cases/7": {
            "close_date": None, "case_tags": "siemantics,ID-42,P3",
            "severity_id": 4, "case_name": "[SIEMantics ID-42] [P3/MEDIUM] sshd brute force @ lab-web01", **case,
        },
        "/case/ioc/list": {"ioc": [{"ioc_value": "185.220.101.45", "ioc_id": 99}]},
        "/case/assets/list": {"assets": [{"asset_name": "lab-web01", "asset_id": 77}]},
    })


def test_correlated_alert_extends_existing_case(fake_iris):
    _open_case(fake_iris)
    assert _add_to_case().case_id == 7

    calls = fake_iris.by_path()
    assert "/manage/cases/add" not in calls
    # A meglevo IoC-t es assetet nem vesszuk fel ujra, az esemeny hozzajuk kapcsolodik.
    assert "/case/ioc/add" not in calls and "/case/assets/add" not in calls
    event = calls["/case/timeline/events/add"][0]
    assert event["event_iocs"] == [99] and event["event_assets"] == [77]
    assert "Correlated with ID-42" in event["event_content"]

    assert calls["/case/notes/groups/add"][0]["group_title"] == "SIEMantics ID-43"
    triage_note = calls["/case/notes/add"][0]["note_content"]
    assert "Correlated with ID-42" in triage_note

    meta = calls["/manage/cases/update/7"][0]
    tags = meta["case_tags"].split(",")
    assert {"ID-42", "ID-43", "correlated", "T1110"} <= set(tags) and len(tags) == len(set(tags))
    # Medium esetet a high riasztas megemeli.
    assert meta["severity_id"] == 5
    assert meta["case_name"] == "[SIEMantics ID-42] [P2/HIGH] sshd brute force @ lab-web01"


def test_correlation_never_lowers_case_severity(fake_iris):
    _open_case(fake_iris, severity_id=6, case_name="[SIEMantics ID-42] [P1/CRITICAL] x")
    _add_to_case()
    meta = fake_iris.by_path()["/manage/cases/update/7"][0]
    assert "severity_id" not in meta and "case_name" not in meta


def test_closed_case_is_not_extended(fake_iris):
    _open_case(fake_iris, close_date="2026-10-01T18:00:00")
    assert _add_to_case() is None
    assert "/case/notes/add" not in fake_iris.by_path()


def test_unreadable_case_is_not_extended(fake_iris):
    fake_iris.failing = {"/manage/cases/7"}
    assert _add_to_case() is None
