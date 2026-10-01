"""Az IRIS eset tartalma (nev, osszefoglalo, note-ok) L2 es Lead Analystok szamara, HTTP nelkul."""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from app.config import settings
from app.mock_engine import severity_bucket
from app.schemas import NormalizedAlert, TriageResult

_SEVERITY_ORDER = ["low", "medium", "high", "critical"]
_PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}

_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")

# Wazuh timestamp formatumok, pl. 2026-10-01T14:20:01.512+0000.
_WAZUH_TS_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z")

# IRIS timeline kategoria, ha a szabalynak nincs MITRE taktikaja.
TIMELINE_DEFAULT_CATEGORY = "Unspecified"

# Compliance mezok a Wazuh szabalyban.
_COMPLIANCE_KEYS = ["pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13"]

_GENERIC_STEPS = [
    "Validate the detection: read the raw log and confirm the activity really happened as described.",
    "Scope: search Wazuh for the same IoCs / rule on other agents in the last 24h (see the pivot queries).",
    "Check whether the affected host or account is business-critical or privileged.",
    "Decide on containment (block IP, isolate host, disable account) and record the decision in the case.",
    "Document findings in this case and set the final classification before closing.",
]

# Vizsgalati lepesek MITRE taktika szerint.
_TACTIC_STEPS = {
    "Initial Access": [
        "Identify the entry vector (exposed service, phishing, valid account) and whether it is still open.",
        "Check for follow-up activity from the same source after the initial event.",
    ],
    "Execution": [
        "Reconstruct the process tree (parent/child) and the full command line; decode any encoded payload.",
        "Collect hashes of the executed binaries/scripts and check them in VirusTotal.",
    ],
    "Persistence": [
        "Look for new services, scheduled tasks/cron jobs, run keys, startup items or new local accounts.",
        "Compare against the host's baseline / FIM (syscheck) history.",
    ],
    "Privilege Escalation": [
        "Review sudo/UAC logs and group membership changes (admins, sudoers, Domain Admins).",
        "Check whether the escalated privileges were used afterwards.",
    ],
    "Defense Evasion": [
        "Verify the security tooling (Wazuh agent, AV/EDR) is still running and reporting on the host.",
        "Look for log clearing, disabled auditing or timestomping around the event time.",
    ],
    "Credential Access": [
        "Check for a successful login from the same source after the failures (compromise indicator).",
        "If credentials may be exposed: reset the password / revoke sessions and tokens of the account.",
        "Verify the account lockout / rate limiting policy worked as expected.",
    ],
    "Discovery": [
        "Determine what was enumerated and whether it is normal for this user/host.",
    ],
    "Lateral Movement": [
        "Identify the destination hosts and check them for the same activity (pivot on the account and source IP).",
        "Review remote logons (RDP/SMB/SSH/WinRM) from the affected host.",
    ],
    "Collection": [
        "Identify which data was accessed or staged and its sensitivity.",
    ],
    "Command and Control": [
        "Check proxy/firewall/DNS logs for further connections to the destination and beaconing patterns.",
        "Block the C2 infrastructure at the perimeter if confirmed.",
    ],
    "Exfiltration": [
        "Quantify outbound data volume to the destination and identify the data involved.",
        "Involve the Lead Analyst / DPO if personal or confidential data may have left the network.",
    ],
    "Impact": [
        "Assess service availability and data integrity on the host; check backups.",
        "Escalate to the Lead Analyst immediately - possible business impact.",
    ],
}

# Vizsgalati lepesek Wazuh szabalycsoport szerint.
_GROUP_STEPS = {
    "authentication_failures": ["Count failed attempts per source and per target account over the last 24h."],
    "authentication_failed": ["Check whether the target account exists and whether it is a service/admin account."],
    "web": ["Check the HTTP response codes/sizes for the requests: did the server answer 200 to the attack?"],
    "attack": ["Check WAF / web application logs for the same source and payload."],
    "sql_injection": ["Review database logs for errors or unusual queries at the event time."],
    "syscheck": ["Diff the changed file against its previous version and identify the user/process that changed it."],
    "rootcheck": ["Verify the rootcheck finding manually on the host (file, process, port)."],
    "vulnerability-detector": ["Confirm the vulnerable package version and plan patching with the asset owner."],
    "sysmon": ["Pull the related Sysmon events (process create, network connect) for the same ProcessGuid."],
}

_ESCALATION_CRITERIA = [
    "Priority P1/P2, or a privileged / service account is involved",
    "Successful compromise is confirmed (login success, payload executed, data accessed)",
    "The same IoC or activity is found on more than one host",
    "Containment requires business approval (isolating a production server, disabling a VIP account)",
]


def _code(value) -> str:
    # Tamado altal irt szoveg inline code-kent, hogy ne legyen elo markdown.
    text = str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    if not text:
        return "-"
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    ticks = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{ticks}{pad}{text}{pad}{ticks}"


def _fence(text: str, lang: str = "") -> str:
    longest = max((len(run) for run in re.findall(r"`{3,}", text)), default=2)
    ticks = "`" * (longest + 1)
    return f"{ticks}{lang}\n{text}\n{ticks}"


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _flatten(data: dict, prefix: str = "") -> list[tuple[str, object]]:
    rows = []
    for key, value in data.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            rows.extend(_flatten(value, f"{path}."))
        else:
            rows.append((path, value))
    return rows


def _table(rows: list[tuple[str, str]], headers: tuple[str, str] = ("Field", "Value")) -> str:
    lines = [f"| {headers[0]} | {headers[1]} |", "| --- | --- |"]
    lines += [f"| {k} | {v} |" for k, v in rows]
    return "\n".join(lines)


def mitre_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def ioc_type_name(value: str) -> str:
    # IRIS IOC tipusnev az ertek alakja alapjan.
    if _IP_RE.match(value):
        return "ip-any"
    if value.startswith(("http://", "https://")):
        return "url"
    if _HEX_RE.match(value) and len(value) in _HASH_TYPES:
        return _HASH_TYPES[len(value)]
    if _DOMAIN_RE.match(value):
        return "domain"
    return "other"


@dataclass
class CaseContext:
    display_id: str
    alert: NormalizedAlert
    triage: TriageResult
    enrichment: list[dict] = field(default_factory=list)
    # Eredeti Wazuh payload, regi rekordoknal ures.
    raw: dict = field(default_factory=dict)
    escalated_by: str | None = None
    # Korrelacional annak a riasztasnak az ID-ja, akinek az esetebe ez bekerult.
    correlated_with: str | None = None

    @property
    def rule(self) -> dict:
        return self.raw.get("rule") or {}

    @property
    def agent(self) -> dict:
        return self.raw.get("agent") or {}

    @property
    def data(self) -> dict:
        return self.raw.get("data") or {}

    @property
    def mitre(self) -> list[tuple[str, str, str]]:
        # (technika ID, nev, taktikak) harmasok.
        mitre = self.rule.get("mitre") or {}
        ids = _as_list(mitre.get("id"))
        names = _as_list(mitre.get("technique"))
        tactics = ", ".join(_as_list(mitre.get("tactic")))
        return [(tid, names[i] if i < len(names) else "", tactics) for i, tid in enumerate(ids)]

    @property
    def tactics(self) -> list[str]:
        return _as_list((self.rule.get("mitre") or {}).get("tactic"))

    @property
    def wazuh_severity(self) -> str:
        return severity_bucket(self.alert.severity)

    @property
    def severity(self) -> str:
        # A Wazuh es az LLM severity kozul a magasabb, az LLM nem csokkentheti.
        llm = (self.triage.recommended_severity or "").lower()
        candidates = [self.wazuh_severity] + ([llm] if llm in _SEVERITY_ORDER else [])
        return max(candidates, key=_SEVERITY_ORDER.index)

    @property
    def priority(self) -> str:
        return _PRIORITY[self.severity]

    @property
    def detected_at(self) -> str:
        return self.raw.get("timestamp") or self.alert.received_at.isoformat(timespec="seconds") + "Z"

    @property
    def siemantics_url(self) -> str | None:
        base = settings.siemantics_public_url.rstrip("/")
        return f"{base}/ui/alert.html?id={self.display_id}" if base else None

    def enrichment_for(self, ioc: str) -> dict | None:
        return next((e for e in self.enrichment if e.get("ioc") == ioc), None)


# --- Case ---

def case_name(ctx: CaseContext) -> str:
    host = f" @ {ctx.alert.agent_name}" if ctx.alert.agent_name else ""
    name = f"[SIEMantics {ctx.display_id}] {priority_tag(ctx.severity)} {ctx.alert.rule_description}{host}"
    return name[:256]


def case_tags(ctx: CaseContext) -> list[str]:
    tags = ["siemantics", ctx.display_id, f"severity:{ctx.severity}", ctx.priority]
    if ctx.escalated_by:
        tags.append("manual-escalation")
    if ctx.correlated_with:
        tags.append("correlated")
    if ctx.rule.get("id"):
        tags.append(f"wazuh-rule:{ctx.rule['id']}")
    tags += [tid for tid, _, _ in ctx.mitre]
    tags += [t.lower().replace(" ", "-") for t in ctx.tactics]
    return list(dict.fromkeys(tags))


def _correlation_line(ctx: CaseContext) -> str:
    return f"Correlated with {ctx.correlated_with}: same source IP and similar alert, added to its case."


def priority_tag(severity: str) -> str:
    return f"[{_PRIORITY[severity]}/{severity.upper()}]"


def severity_rank(name: str | None) -> int:
    # Ismeretlen severity (pl. IRIS Unspecified) a legalacsonyabb.
    name = (name or "").lower()
    return _SEVERITY_ORDER.index(name) if name in _SEVERITY_ORDER else -1


def raise_case_name(case_name_: str, ctx: CaseContext) -> str:
    # A meglevo eset neveben a prioritas cimket a magasabbra csereljuk.
    return re.sub(r"\[P\d/[A-Z]+\]", priority_tag(ctx.severity), case_name_, count=1)[:256]


def _verdict_line(ctx: CaseContext) -> str:
    t = ctx.triage
    model = f" / {t.model}" if t.model else ""
    if ctx.escalated_by:
        return (
            f"**Manually escalated by {ctx.escalated_by}** - the automatic triage did not escalate this alert "
            f"(see the triage note for the original verdict)."
        )
    return f"Automatic triage verdict: **TRUE POSITIVE**, confidence **{t.confidence:.0%}** ({t.engine}{model})."


def _key_facts(ctx: CaseContext) -> list[tuple[str, str]]:
    a = ctx.alert
    rule_id = ctx.rule.get("id")
    rows = [
        ("SIEMantics ID", f"**{ctx.display_id}**"),
        ("Wazuh alert ID", _code(a.alert_id)),
        ("Priority / severity", f"**{ctx.priority} / {ctx.severity.upper()}** "
                                f"(Wazuh level {a.severity} = {ctx.wazuh_severity}, "
                                f"triage recommendation: {ctx.triage.recommended_severity or '-'})"),
        ("Detected at", _code(ctx.detected_at)),
        ("Rule", f"{_code(rule_id) + ' - ' if rule_id else ''}{_code(a.rule_description)}"),
    ]
    if ctx.mitre:
        rows.append(("MITRE ATT&CK", "<br>".join(
            f"[{tid}]({mitre_url(tid)}) {name} ({tactics})" for tid, name, tactics in ctx.mitre
        )))
    host = ctx.agent.get("name") or a.agent_name
    if host:
        details = ", ".join(f"{k} {_code(v)}" for k, v in (("agent", ctx.agent.get("id")), ("ip", ctx.agent.get("ip"))) if v)
        rows.append(("Affected host", f"{_code(host)}" + (f" ({details})" if details else "")))
    src = ctx.data.get("srcip") or a.source_ip
    if src:
        port = ctx.data.get("srcport")
        rows.append(("Source", _code(f"{src}:{port}" if port else src)))
    for label, key in (("Destination", "dstip"), ("Target user", "dstuser"), ("Source user", "srcuser")):
        if ctx.data.get(key):
            rows.append((label, _code(ctx.data[key])))
    if ctx.raw.get("location"):
        rows.append(("Log source", _code(ctx.raw["location"])))
    rows.append(("IoCs", ", ".join(_code(i) for i in ctx.triage.iocs) or "none extracted"))
    return rows


def case_description(ctx: CaseContext) -> str:
    parts = [
        f"## {ctx.priority} - {ctx.alert.rule_description}",
        _verdict_line(ctx),
        _table(_key_facts(ctx)),
        "### Triage reasoning",
        ctx.triage.reasoning,
        "### First steps for L2",
        "\n".join(f"1. {step}" for step in _investigation_steps(ctx)[:3]),
        "Full evidence, threat intelligence and the investigation checklist are in the "
        f"**SIEMantics {ctx.display_id}** notes group.",
    ]
    if ctx.siemantics_url:
        parts.append(f"SIEMantics record: {ctx.siemantics_url}")
    return "\n\n".join(parts)


# --- Notes ---

def _triage_note(ctx: CaseContext) -> str:
    t = ctx.triage
    rows = [
        ("Verdict", "true positive" if t.is_true_positive else "false positive"),
        ("Confidence", f"{t.confidence:.0%}"),
        ("Engine / model", f"{t.engine} / {_code(t.model) if t.model else '-'}"),
        ("Wazuh level", f"{ctx.alert.severity} ({ctx.wazuh_severity})"),
        ("Recommended severity", t.recommended_severity or "-"),
        ("Case priority", f"**{ctx.priority} / {ctx.severity.upper()}** (higher of Wazuh and triage)"),
        ("Escalation", f"manual, by {ctx.escalated_by}" if ctx.escalated_by else "automatic"),
    ]
    if ctx.correlated_with:
        rows.append(("Correlation", _correlation_line(ctx)))
    return "\n\n".join([
        *([f"**{_correlation_line(ctx)}**"] if ctx.correlated_with else []),
        _verdict_line(ctx),
        _table(rows),
        "## Reasoning",
        t.reasoning,
        "> The triage is an automated first opinion (LLM or rule-based fallback). "
        "Treat it as a lead, not as evidence - verify against the raw log.",
    ])


def _alert_note(ctx: CaseContext) -> str:
    rule = ctx.rule
    rule_rows = [
        ("Rule ID", _code(rule.get("id") or "-")),
        ("Level", str(ctx.alert.severity)),
        ("Description", _code(ctx.alert.rule_description)),
        ("Groups", ", ".join(_code(g) for g in _as_list(rule.get("groups"))) or "-"),
    ]
    if rule.get("firedtimes") is not None:
        rule_rows.append(("Fired times", str(rule["firedtimes"])))
    if rule.get("frequency") is not None:
        rule_rows.append(("Frequency", str(rule["frequency"])))
    for key in _COMPLIANCE_KEYS:
        if rule.get(key):
            rule_rows.append((key.upper(), ", ".join(_code(v) for v in _as_list(rule[key]))))

    parts = ["## Rule", _table(rule_rows)]

    if ctx.mitre:
        parts += ["## MITRE ATT&CK", _table(
            [(f"[{tid}]({mitre_url(tid)})", f"{name} - {tactics}") for tid, name, tactics in ctx.mitre],
            headers=("Technique", "Name - tactic"),
        )]

    source_rows = []
    for label, value in (
        ("Agent", ctx.agent.get("name") or ctx.alert.agent_name),
        ("Agent ID", ctx.agent.get("id")),
        ("Agent IP", ctx.agent.get("ip")),
        ("Manager", (ctx.raw.get("manager") or {}).get("name")),
        ("Decoder", (ctx.raw.get("decoder") or {}).get("name")),
        ("Location", ctx.raw.get("location")),
        ("Event time (Wazuh)", ctx.raw.get("timestamp")),
        ("Received by SIEMantics", ctx.alert.received_at.isoformat(timespec="seconds") + "Z"),
    ):
        if value:
            source_rows.append((label, _code(value)))
    parts += ["## Event source", _table(source_rows)]

    if ctx.data:
        parts += ["## Decoded fields (`data.*`)", _table(
            [(_code(k), _code(v if not isinstance(v, list) else ", ".join(map(str, v)))) for k, v in _flatten(ctx.data)]
        )]
    return "\n\n".join(parts)


def _threat_intel_note(ctx: CaseContext) -> str:
    if not ctx.triage.iocs:
        return "No IoCs were extracted from this alert."

    rows = []
    for ioc in ctx.triage.iocs:
        entry = ctx.enrichment_for(ioc) or {}
        vt = entry.get("virustotal")
        abuse = entry.get("abuseipdb")
        vt_cell = (
            f"{vt['malicious']} malicious / {vt['suspicious']} suspicious / {vt.get('harmless', 0)} harmless, "
            f"reputation {vt.get('reputation')}, {vt.get('country') or '?'}, AS {_code(vt.get('as_owner') or '?')}"
            if vt else "-"
        )
        abuse_cell = (
            f"{abuse['abuse_confidence_score']}% confidence, {abuse.get('total_reports', 0)} reports, "
            f"{abuse.get('country_code') or '?'}, {_code(abuse.get('isp') or 'unknown ISP')}"
            + (" (whitelisted)" if abuse.get("is_whitelisted") else "")
            if abuse else "-"
        )
        rows.append(f"| {_code(ioc)} | {ioc_type_name(ioc)} | {vt_cell} | {abuse_cell} |")

    table = "\n".join(["| IoC | Type | VirusTotal | AbuseIPDB |", "| --- | --- | --- | --- |", *rows])
    parts = [table]
    if not ctx.enrichment:
        parts.append(
            "> No threat intelligence lookup ran (no VirusTotal/AbuseIPDB key configured, or no IP-type IoC). "
            "Check the IoCs manually."
        )
    parts.append(
        "Manual lookups: "
        + ", ".join(
            f"[VT](https://www.virustotal.com/gui/search/{quote(ioc, safe='')}) {_code(ioc)}" for ioc in ctx.triage.iocs
        )
    )
    return "\n\n".join(parts)


def _investigation_steps(ctx: CaseContext) -> list[str]:
    steps: list[str] = []
    for tactic in ctx.tactics:
        steps += _TACTIC_STEPS.get(tactic, [])
    for group in _as_list(ctx.rule.get("groups")):
        steps += _GROUP_STEPS.get(group, [])
    steps += _GENERIC_STEPS
    return list(dict.fromkeys(steps))


def _pivot_queries(ctx: CaseContext) -> list[str]:
    queries = []
    src = ctx.data.get("srcip") or ctx.alert.source_ip
    if src:
        queries.append(f"data.srcip:{src}")
    host = ctx.agent.get("name") or ctx.alert.agent_name
    if host:
        queries.append(f"agent.name:{host} AND rule.level >= 7")
    if ctx.rule.get("id"):
        queries.append(f"rule.id:{ctx.rule['id']}")
    for key in ("dstuser", "srcuser"):
        if ctx.data.get(key):
            queries.append(f"data.{key}:{ctx.data[key]}")
    return queries


def _checklist_note(ctx: CaseContext) -> str:
    parts = [
        "## Investigation steps",
        "\n".join(f"- [ ] {step}" for step in _investigation_steps(ctx)),
    ]
    queries = _pivot_queries(ctx)
    if queries:
        parts += [
            "## Pivot queries (Wazuh dashboard / Discover, last 24h)",
            _fence("\n".join(queries)),
        ]
    parts += [
        "## Escalate to the Lead Analyst if",
        "\n".join(f"- {c}" for c in _ESCALATION_CRITERIA),
        f"This case is **{ctx.priority}**"
        + (" - Lead Analyst review required." if ctx.priority in ("P1", "P2") else "."),
    ]
    return "\n\n".join(parts)


def _evidence_note(ctx: CaseContext) -> str:
    parts = ["## Full log", _fence(ctx.raw.get("full_log") or ctx.alert.log_snippet or "(empty)")]
    if ctx.raw:
        parts += ["## Original Wazuh alert (JSON)", _fence(json.dumps(ctx.raw, indent=2, ensure_ascii=False), "json")]
    else:
        parts.append("> The original Wazuh payload was not stored for this record.")
    return "\n\n".join(parts)


def case_notes(ctx: CaseContext) -> list[tuple[str, str]]:
    # (cim, markdown) parok olvasasi sorrendben.
    return [
        ("1. Triage summary", _triage_note(ctx)),
        ("2. Alert details", _alert_note(ctx)),
        ("3. Threat intelligence", _threat_intel_note(ctx)),
        ("4. Investigation checklist", _checklist_note(ctx)),
        ("5. Raw evidence", _evidence_note(ctx)),
    ]


# --- IOCs / assets ---

def ioc_description(ctx: CaseContext, ioc: str) -> str:
    roles = []
    if ioc == (ctx.data.get("srcip") or ctx.alert.source_ip):
        roles.append("source IP of the alert")
    if ioc == ctx.data.get("dstip"):
        roles.append("destination IP of the alert")
    lines = [f"Extracted by SIEMantics from {ctx.display_id} ({ctx.alert.rule_description})"
             + (f" - {', '.join(roles)}" if roles else "") + "."]

    entry = ctx.enrichment_for(ioc) or {}
    if entry.get("virustotal"):
        vt = entry["virustotal"]
        lines.append(f"VirusTotal: {vt['malicious']} malicious / {vt['suspicious']} suspicious.")
    if entry.get("abuseipdb"):
        abuse = entry["abuseipdb"]
        lines.append(f"AbuseIPDB: {abuse['abuse_confidence_score']}% confidence, {abuse.get('total_reports', 0)} reports.")
    return " ".join(lines)


def ioc_tags(ctx: CaseContext) -> str:
    return ",".join(["siemantics", ctx.display_id] + [tid for tid, _, _ in ctx.mitre])


def asset_os(ctx: CaseContext) -> str:
    groups = " ".join(_as_list(ctx.rule.get("groups"))).lower()
    location = (ctx.raw.get("location") or "").lower()
    return "windows" if "windows" in groups or "sysmon" in groups or "eventchannel" in location else "linux"


def asset_description(ctx: CaseContext) -> str:
    agent_id = ctx.agent.get("id")
    return (
        f"Wazuh agent{f' {agent_id}' if agent_id else ''} that raised {ctx.display_id} "
        f"({ctx.alert.rule_description}) at {ctx.detected_at}."
    )


# --- Timeline ---

def event_time(ctx: CaseContext) -> tuple[str, str]:
    # IRIS kulon varja az idopontot (idozona nelkul) es az idozonat.
    ts = None
    for fmt in _WAZUH_TS_FORMATS:
        try:
            ts = datetime.strptime(ctx.raw.get("timestamp") or "", fmt)
            break
        except ValueError:
            continue
    if ts is None:
        ts = ctx.alert.received_at.replace(tzinfo=timezone.utc)

    offset = ts.utcoffset() or timedelta(0)
    minutes = abs(int(offset.total_seconds())) // 60
    tz = f"{'-' if offset < timedelta(0) else '+'}{minutes // 60:02d}:{minutes % 60:02d}"
    return ts.replace(tzinfo=None).isoformat(timespec="milliseconds"), tz


def timeline_category(ctx: CaseContext) -> str:
    return ctx.tactics[0] if ctx.tactics else TIMELINE_DEFAULT_CATEGORY


def timeline_title(ctx: CaseContext) -> str:
    return f"{ctx.display_id} - {ctx.alert.rule_description}"[:255]


def timeline_content(ctx: CaseContext) -> str:
    t = ctx.triage
    verdict = (
        f"manually escalated by {ctx.escalated_by}"
        if ctx.escalated_by
        else f"triage: true positive, {t.confidence:.0%} ({t.engine})"
    )
    lines = [f"**{ctx.priority} / {ctx.severity.upper()}** - {verdict}"]

    facts = []
    host = ctx.agent.get("name") or ctx.alert.agent_name
    if host:
        facts.append(f"Host: {_code(host)}")
    src = ctx.data.get("srcip") or ctx.alert.source_ip
    if src:
        port = ctx.data.get("srcport")
        facts.append(f"Source: {_code(f'{src}:{port}' if port else src)}")
    if ctx.data.get("dstuser"):
        facts.append(f"Target user: {_code(ctx.data['dstuser'])}")
    if facts:
        lines.append(" - ".join(facts))

    if ctx.mitre:
        lines.append("MITRE: " + ", ".join(f"[{tid}]({mitre_url(tid)}) {name}" for tid, name, _ in ctx.mitre))
    if ctx.correlated_with:
        lines.append(_correlation_line(ctx))
    lines.append(f"Details: notes group **SIEMantics {ctx.display_id}**.")
    return "\n\n".join(lines)


def timeline_raw(ctx: CaseContext) -> str:
    return ctx.raw.get("full_log") or ctx.alert.log_snippet or ""


def timeline_source(ctx: CaseContext) -> str:
    location = ctx.raw.get("location")
    return f"Wazuh{f' ({location})' if location else ''} via SIEMantics"[:255]
