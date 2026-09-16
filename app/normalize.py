from app.schemas import WazuhAlertPayload, NormalizedAlert

LOG_SNIPPET_MAX_LEN = 1000


def normalize_wazuh_alert(payload: WazuhAlertPayload) -> NormalizedAlert:
    source_ip = payload.data.get("srcip") or (payload.agent.ip if payload.agent else None)
    log_snippet = (payload.full_log or "")[:LOG_SNIPPET_MAX_LEN]

    return NormalizedAlert(
        alert_id=payload.id or "unknown",
        source_ip=source_ip,
        agent_name=payload.agent.name if payload.agent else None,
        rule_description=payload.rule.description,
        severity=payload.rule.level,
        log_snippet=log_snippet,
    )
