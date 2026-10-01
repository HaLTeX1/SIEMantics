import ipaddress
import json

from app.schemas import NormalizedAlert, WazuhAlertPayload

LOG_SNIPPET_MAX_LEN = 1000

# Event fields handed to the LLM / shown in the ticket: per-value and total caps
# keep the prompt small even for huge events (e.g. a full Windows event).
EVENT_FIELD_MAX_LEN = 500
EVENT_FIELDS_MAX_COUNT = 60
EVENT_FIELDS_MAX_TOTAL_LEN = 4000

# Where integrations other than plain syslog put the source address, in order of preference
_SOURCE_IP_FIELDS = (
    ("srcip",),
    ("src_ip",),
    ("win", "eventdata", "ipAddress"),
    ("aws", "sourceIPAddress"),
    ("office365", "ClientIP"),
    ("gcp", "protoPayload", "requestMetadata", "callerIp"),
)

# Top-level Wazuh alert fields (besides `data`) that carry event details
_EXTRA_EVENT_SECTIONS = ("syscheck", "previous_output")


def _clean_ip(value) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().strip("[]")
    candidates = [value]
    if value.count(":") == 1:  # "1.2.3.4:5678"
        candidates.append(value.split(":")[0])
    for candidate in candidates:
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_unspecified:
            return None
        return str(ip)
    return None


def _dig(data: dict, path: tuple[str, ...]):
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _source_ip(payload: WazuhAlertPayload) -> str | None:
    for path in _SOURCE_IP_FIELDS:
        ip = _clean_ip(_dig(payload.data, path))
        if ip:
            return ip
    return payload.agent.ip if payload.agent else None


def _flatten(value, prefix: str, out: list[tuple[str, str]]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _flatten(child, f"{prefix}.{key}" if prefix else str(key), out)
    elif isinstance(value, list):
        if all(not isinstance(v, (dict, list)) for v in value):
            if value:
                out.append((prefix, ", ".join(str(v) for v in value)))
        else:
            for i, child in enumerate(value):
                _flatten(child, f"{prefix}[{i}]", out)
    elif value is not None and value != "":
        out.append((prefix, str(value)))


def _event_fields(payload: WazuhAlertPayload) -> dict[str, str]:
    leaves: list[tuple[str, str]] = []
    _flatten(payload.data, "data", leaves)
    extra = payload.model_extra or {}
    for section in _EXTRA_EVENT_SECTIONS:
        _flatten(extra.get(section), section, leaves)

    fields: dict[str, str] = {}
    total = 0
    for key, value in leaves:
        if len(value) > EVENT_FIELD_MAX_LEN:
            value = value[: EVENT_FIELD_MAX_LEN - 1] + "…"
        total += len(key) + len(value)
        if len(fields) >= EVENT_FIELDS_MAX_COUNT or total > EVENT_FIELDS_MAX_TOTAL_LEN:
            fields["_truncated"] = f"{len(leaves) - len(fields)} more field(s) omitted"
            break
        fields[key] = value
    return fields


def _str_list(value) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        value = [value]
    return [str(v) for v in value if v not in (None, "")]


def normalize_wazuh_alert(payload: WazuhAlertPayload) -> NormalizedAlert:
    log_snippet = (payload.full_log or "")[:LOG_SNIPPET_MAX_LEN]
    rule_extra = payload.rule.model_extra or {}
    mitre = rule_extra.get("mitre") if isinstance(rule_extra.get("mitre"), dict) else {}
    decoder = (payload.model_extra or {}).get("decoder")

    return NormalizedAlert(
        alert_id=payload.id or "unknown",
        source_ip=_source_ip(payload),
        agent_name=payload.agent.name if payload.agent else None,
        rule_description=payload.rule.description,
        severity=payload.rule.level,
        log_snippet=log_snippet,
        timestamp=payload.timestamp,
        rule_id=payload.rule.id,
        rule_groups=_str_list(payload.rule.groups),
        mitre_ids=_str_list(mitre.get("id")),
        mitre_tactics=_str_list(mitre.get("tactic")),
        mitre_techniques=_str_list(mitre.get("technique")),
        agent_id=payload.agent.id if payload.agent else None,
        agent_ip=payload.agent.ip if payload.agent else None,
        location=payload.location,
        decoder=decoder.get("name") if isinstance(decoder, dict) else None,
        event_fields=_event_fields(payload),
    )


def related_log_excerpt(raw_payload: dict | None, limit: int = 300) -> str:
    """Short log line of a stored alert, for the related-alerts context."""
    if not raw_payload:
        return ""
    log = raw_payload.get("full_log") or json.dumps(raw_payload.get("data") or {}, ensure_ascii=False)
    log = " ".join(str(log).split())
    return log if len(log) <= limit else log[: limit - 1] + "…"
