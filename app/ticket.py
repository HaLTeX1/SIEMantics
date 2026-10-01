"""Renders the DFIR-IRIS case (name, description, analysis note) for an alert.

Pure functions only, so the ticket layout is testable without IRIS. Everything
that comes from the alert is attacker-controlled, and the LLM text can be
steered by it too: values go into code spans/fences, and free text is stripped
of raw HTML and image embeds before it reaches the IRIS markdown renderer."""

import ipaddress
import re

from app.schemas import NormalizedAlert, RelatedAlert, TriageResult

CASE_NAME_MAX_LEN = 256
EVENT_FIELDS_IN_NOTE = 40

_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://\S+$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
_WIN_PATH_RE = re.compile(r"^[A-Za-z]:\\")


def classify_ioc(value: str) -> str:
    """IRIS (MISP-style) IoC type name for a value; "other" if unsure."""
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return "ip-any"
    except ValueError:
        pass
    if _HEX_RE.match(value) and len(value) in _HASH_TYPES:
        return _HASH_TYPES[len(value)]
    if _URL_RE.match(value):
        return "url"
    if _EMAIL_RE.match(value):
        return "email"
    if value.startswith("/") or _WIN_PATH_RE.match(value):
        return "filename"
    if _DOMAIN_RE.match(value):
        return "domain"
    return "other"


# --- markdown helpers

def _code(value) -> str:
    """Inline code span for an untrusted value (no markdown/HTML interpretation)."""
    text = " ".join(str(value).split()).replace("`", "'")
    return f"`{text}`" if text else "-"


def _fence(text: str) -> str:
    """Fenced block that the text itself cannot close."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{text}\n{fence}"


def _text(value: str) -> str:
    """Free text (LLM output): keep markdown, but no raw HTML and no image embeds
    (an image URL would make IRIS fetch an attacker-chosen address)."""
    return value.replace("<", "&lt;").replace("![", "!\\[")


def _cell(value) -> str:
    return _text(" ".join(str(value).split())).replace("|", "\\|") or "-"


def _bullets(items: list[str], numbered: bool = False) -> str:
    return "\n".join(f"{i}. {_text(item)}" if numbered else f"- {_text(item)}" for i, item in enumerate(items, 1))


def format_enrichment(enrichment: list[dict]) -> str:
    lines = []
    for entry in enrichment:
        vt = entry.get("virustotal")
        abuse = entry.get("abuseipdb")

        parts = []
        if vt:
            parts.append(
                f"VT: {vt['malicious']} malicious / {vt['suspicious']} suspicious "
                f"(reputation {vt.get('reputation')}, {vt.get('country') or '?'})"
            )
        if abuse:
            parts.append(
                f"AbuseIPDB: {abuse['abuse_confidence_score']}% confidence, "
                f"{abuse.get('total_reports', 0)} reports ({abuse.get('country_code') or '?'}, "
                f"{_text(abuse.get('isp') or 'unknown ISP')})"
            )
        if not parts:
            parts.append("no enrichment data available")

        lines.append(f"- {_code(entry['ioc'])} - " + "; ".join(parts))
    return "\n".join(lines)


# --- case fields

def _host(alert: NormalizedAlert) -> str | None:
    return alert.agent_name if alert.agent_id != "000" else None


def render_case_name(alert: NormalizedAlert, display_id: str) -> str:
    name = f"[SIEMantics {display_id}] {alert.rule_description}"
    host = _host(alert)
    if host:
        name += f" on {host}"
    return name[:CASE_NAME_MAX_LEN]


def render_case_description(alert: NormalizedAlert, triage: TriageResult) -> str:
    lead = triage.summary or triage.reasoning
    facts = [
        f"Severity: {triage.recommended_severity or '-'} (Wazuh level {alert.severity})",
        f"Host: {alert.agent_name or '-'}" + (f" ({alert.agent_ip})" if alert.agent_ip else ""),
    ]
    if alert.source_ip and alert.source_ip != alert.agent_ip:
        facts.append(f"Source IP: {alert.source_ip}")
    facts.append(f"Triage: {triage.engine}, confidence {triage.confidence}")
    return _text(lead) + "\n\n" + " | ".join(facts) + "\n\nSee the SIEMantics note for the full analysis."


def _mitre_from_rule(alert: NormalizedAlert) -> str | None:
    if not alert.mitre_ids:
        return None
    techniques = [
        f"{mid} {alert.mitre_techniques[i]}" if i < len(alert.mitre_techniques) else mid
        for i, mid in enumerate(alert.mitre_ids)
    ]
    text = ", ".join(techniques)
    if alert.mitre_tactics:
        text += f" ({', '.join(alert.mitre_tactics)})"
    return _text(text)


def _alert_details(alert: NormalizedAlert) -> list[str]:
    lines = []
    if alert.timestamp:
        lines.append(f"- **Event time:** {_code(alert.timestamp)}")
    lines.append(f"- **Received:** {alert.received_at.isoformat(timespec='seconds')} UTC")

    host = _code(alert.agent_name or "-")
    host_extra = [part for part in (alert.agent_ip, f"agent {alert.agent_id}" if alert.agent_id else None) if part]
    if host_extra:
        host += f" ({', '.join(_text(p) for p in host_extra)})"
    lines.append(f"- **Host:** {host}")

    rule = f"{_code(alert.rule_id)} " if alert.rule_id else ""
    lines.append(f"- **Rule:** {rule}{_text(alert.rule_description)} (level {alert.severity})")
    if alert.rule_groups:
        lines.append(f"- **Rule groups:** {_text(', '.join(alert.rule_groups))}")
    mitre = _mitre_from_rule(alert)
    if mitre:
        lines.append(f"- **MITRE ATT&CK (Wazuh rule):** {mitre}")
    if alert.location or alert.decoder:
        source = _code(alert.location or "-")
        if alert.decoder:
            source += f" (decoder {_code(alert.decoder)})"
        lines.append(f"- **Log source:** {source}")
    # source_ip falls back to the agent's own IP - only worth a line when it is another host
    if alert.source_ip and alert.source_ip != alert.agent_ip:
        lines.append(f"- **Source IP:** {_code(alert.source_ip)}")
    if alert.alert_id and alert.alert_id != "unknown":
        lines.append(f"- **Wazuh search:** {_code(f'id:\"{alert.alert_id}\"')}")
    return lines


def _related_table(related: list[RelatedAlert]) -> str:
    rows = [
        "| Alert | Received (UTC) | Level | Rule | Host / source IP | Status | IRIS case |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in related:
        where = " / ".join(v for v in (r.agent_name, r.source_ip) if v) or "-"
        rows.append(
            f"| {r.display_id} | {r.received_at.isoformat(sep=' ', timespec='seconds')} | {r.severity} "
            f"| {_cell(r.rule_description)} | {_cell(where)} | {r.status.value} "
            f"| {r.iris_case_id if r.iris_case_id is not None else '-'} |"
        )
    excerpts = [f"- **{r.display_id}:** {_code(r.log_excerpt)}" for r in related if r.log_excerpt]
    if excerpts:
        rows.append("\nLog excerpts:\n" + "\n".join(excerpts))
    return "\n".join(rows)


def render_case_note(
    alert: NormalizedAlert,
    triage: TriageResult,
    enrichment: list[dict] | None,
    *,
    display_id: str,
    escalated_by: str | None = None,
    related: list[RelatedAlert] | None = None,
    related_window_hours: int = 24,
    alert_url: str | None = None,
) -> str:
    sections: list[str] = []

    if triage.summary:
        sections.append(f"**{_text(triage.summary)}**")

    header = f"SIEMantics alert **{display_id}** (Wazuh alert ID {_code(alert.alert_id)})"
    if alert_url:
        header += f" - [open in SIEMantics]({alert_url})"
    if escalated_by:
        header += (
            f"\n\n**Manually escalated by {_text(escalated_by)}** - "
            "the automatic triage did not escalate this alert."
        )
    sections.append(header)

    verdict = "True positive" if triage.is_true_positive else "False positive"
    verdict_lines = [
        f"- **Verdict:** {verdict} (confidence {triage.confidence})",
        f"- **Recommended severity:** {triage.recommended_severity or '-'} (Wazuh level {alert.severity})",
        f"- **Triage engine:** {triage.engine}" + (f" ({_text(triage.model)})" if triage.model else ""),
    ]
    if triage.engine == "mock":
        verdict_lines.append(
            "- _Rule-based fallback engine (LLM unavailable): there is no analysis or action plan, "
            "triage this alert manually._"
        )
    sections.append("## Verdict\n\n" + "\n".join(verdict_lines))

    sections.append("## Alert details\n\n" + "\n".join(_alert_details(alert)))

    analysis = ["## Analysis\n\n" + _text(triage.reasoning)]
    if triage.potential_impact:
        analysis.append("### Potential impact\n\n" + _text(triage.potential_impact))
    if triage.benign_explanations:
        analysis.append("### Possible benign explanations\n\n" + _bullets(triage.benign_explanations))
    if triage.mitre_techniques:
        analysis.append("### MITRE ATT&CK (analysis)\n\n" + _bullets(triage.mitre_techniques))
    sections.append("\n\n".join(analysis))

    if triage.immediate_actions:
        sections.append("## Immediate actions (L1)\n\n" + _bullets(triage.immediate_actions, numbered=True))
    if triage.investigation_steps:
        sections.append("## Investigation steps (L2)\n\n" + _bullets(triage.investigation_steps, numbered=True))
    if triage.escalation_criteria:
        sections.append("## Escalate to incident response if\n\n" + _bullets(triage.escalation_criteria))
    if triage.missing_information:
        sections.append("## Missing information\n\n" + _bullets(triage.missing_information))

    title = f"## Related alerts (same host or source IP, within {related_window_hours}h)"
    sections.append(f"{title}\n\n" + (_related_table(related) if related else "None found."))

    if triage.iocs:
        iocs = "\n".join(f"- {_code(ioc)} ({classify_ioc(ioc)})" for ioc in triage.iocs)
        sections.append("## Indicators of compromise\n\n" + iocs)
    if enrichment:
        sections.append("## Threat intelligence\n\n" + format_enrichment(enrichment))

    if alert.event_fields:
        items = list(alert.event_fields.items())
        lines = [f"- {_code(key)}: {_code(value)}" for key, value in items[:EVENT_FIELDS_IN_NOTE]]
        if len(items) > EVENT_FIELDS_IN_NOTE:
            lines.append(f"- _{len(items) - EVENT_FIELDS_IN_NOTE} more field(s) in the original alert_")
        sections.append("## Event fields\n\n" + "\n".join(lines))

    if alert.log_snippet:
        sections.append("## Original log\n\n" + _fence(alert.log_snippet))

    return "\n\n".join(sections) + "\n"
