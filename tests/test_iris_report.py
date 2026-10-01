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
    ioc_description,
    ioc_type_name,
    mitre_url,
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


@pytest.fixture
def fake_iris(monkeypatch):
    calls: list[tuple[str, str, dict | None]] = []
    lookups = {
        "/manage/ioc-types/list": [{"type_name": "ip-any", "type_id": 76}, {"type_name": "other", "type_id": 96}],
        "/manage/asset-type/list": [{"asset_name": "Linux - Server", "asset_id": 3}],
        "/manage/severities/list": [{"severity_name": "High", "severity_id": 5}],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        calls.append((request.method, request.url.path, body))
        path = request.url.path
        if path in lookups:
            return httpx.Response(200, json={"data": lookups[path]})
        if path == "/case/assets/add":
            return httpx.Response(400, json={"message": "rejected"})
        return httpx.Response(200, json={"data": {"case_id": 7, "group_id": 9}})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        iris_module.httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw)
    )
    return calls


def test_iris_client_sends_full_case(fake_iris):
    ctx = _ctx()
    client = iris_module.IrisClient()
    result = asyncio.run(client.create_case_from_alert(
        ctx.alert, ctx.triage, ctx.enrichment, display_id="ID-42", raw_payload=SSH_BRUTE_FORCE
    ))
    assert result.case_id == 7

    by_path = {}
    for _, path, body in fake_iris:
        by_path.setdefault(path, []).append(body)
    assert by_path["/manage/cases/add"][0]["case_name"].startswith("[SIEMantics ID-42]")
    assert by_path["/case/notes/groups/add"][0]["group_title"] == "SIEMantics ID-42"
    assert len(by_path["/case/notes/add"]) == 5
    ioc = by_path["/case/ioc/add"][0]
    assert ioc["ioc_type_id"] == 76 and "ID-42" in ioc["ioc_tags"]
    # Az asset hiba ellenere az eset elkeszul.
    assert by_path["/manage/cases/update/7"][0]["severity_id"] == 5
    assert "T1110" in by_path["/manage/cases/update/7"][0]["case_tags"]
