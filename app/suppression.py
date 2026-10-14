# Suppression szabalyok: az elemzo altal elhallgattatott riasztasok LLM nelkul SUPPRESSED-ek.

import logging
from datetime import datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation import join_group
from app.enums import AlertStatus
from app.models import AlertRecord, SuppressionRule, User

logger = logging.getLogger("siemantics.suppression")

SCOPES = ("exact", "rule_host", "rule")
# Ezek a statuszok nyomhatok el utolag; IRIS esettel rendelkezo riasztas soha.
_RETROACTIVE = (AlertStatus.NEEDS_REVIEW, AlertStatus.SUPPRESSED, AlertStatus.ERROR)


class SuppressionError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _key(record: AlertRecord, scope: str) -> tuple[str | None, str | None, str | None]:
    # (fingerprint, rule_id, agent_name) a hatokor szerint; hianyzo mezonel hiba.
    if scope == "exact":
        if not record.fingerprint:
            raise SuppressionError(422, f"{record.display_id} has no fingerprint, use a rule scope")
        return record.fingerprint, None, None
    if not record.rule_id:
        raise SuppressionError(422, f"{record.display_id} has no Wazuh rule ID")
    if scope == "rule_host":
        if not record.agent_name:
            raise SuppressionError(422, f"{record.display_id} has no host, use the rule scope")
        return None, record.rule_id, record.agent_name
    return None, record.rule_id, None


def matches(rule: SuppressionRule, record: AlertRecord) -> bool:
    if rule.scope == "exact":
        return bool(record.fingerprint) and record.fingerprint == rule.fingerprint
    if not record.rule_id or record.rule_id != rule.rule_id:
        return False
    return rule.scope == "rule" or record.agent_name == rule.agent_name


def _live():
    now = datetime.utcnow()
    return SuppressionRule.is_active.is_(True), or_(SuppressionRule.expires_at.is_(None), SuppressionRule.expires_at > now)


def _record_filter(rule: SuppressionRule):
    if rule.scope == "exact":
        return [AlertRecord.fingerprint == rule.fingerprint]
    conditions = [AlertRecord.rule_id == rule.rule_id]
    if rule.scope == "rule_host":
        conditions.append(AlertRecord.agent_name == rule.agent_name)
    return conditions


async def find_suppression(session: AsyncSession, record: AlertRecord) -> SuppressionRule | None:
    keys = []
    if record.fingerprint:
        keys.append(SuppressionRule.fingerprint == record.fingerprint)
    if record.rule_id:
        keys.append(SuppressionRule.rule_id == record.rule_id)
    if not keys:
        return None
    result = await session.execute(select(SuppressionRule).where(*_live(), or_(*keys)).order_by(SuppressionRule.id))
    return next((rule for rule in result.scalars() if matches(rule, record)), None)


async def _anchor(session: AsyncSession, rule: SuppressionRule, exclude_id: int) -> AlertRecord | None:
    # A szabaly elso talalata, ehhez csoportosul a tobbi.
    result = await session.execute(
        select(AlertRecord)
        .where(AlertRecord.suppression_rule_id == rule.id, AlertRecord.id != exclude_id)
        .order_by(AlertRecord.received_at)
        .limit(1)
    )
    return result.scalars().first()


def _note(rule: SuppressionRule) -> str:
    text = f"suppression rule #{rule.id}"
    return f"{text}: {rule.reason}" if rule.reason else text


async def apply_rule(session: AsyncSession, rule: SuppressionRule, record: AlertRecord) -> None:
    # Uj riasztas elnyomasa triazs nelkul; a commit a hivo dolga.
    now = datetime.utcnow()
    record.status = record.auto_status = AlertStatus.SUPPRESSED
    record.triage_engine = "suppression"
    record.suppression_rule_id = rule.id
    record.review_reason = _note(rule)
    record.llm_reasoning = f"Suppressed by {_note(rule)} (set by an analyst), no triage."
    rule.hit_count += 1
    rule.last_hit_at = now
    anchor = await _anchor(session, rule, record.id)
    if anchor is not None:
        join_group(record, anchor)


async def _suppress_existing(session: AsyncSession, rule: SuppressionRule) -> list[AlertRecord]:
    # Meglevo, IRIS eset nelkuli egyezo riasztasok elnyomasa; az auto_status a metrikakhoz megmarad.
    result = await session.execute(
        select(AlertRecord)
        .where(
            *_record_filter(rule),
            AlertRecord.iris_case_id.is_(None),
            AlertRecord.status.in_(_RETROACTIVE),
            AlertRecord.suppression_rule_id.is_(None),
        )
        .order_by(AlertRecord.received_at)
    )
    records = [r for r in result.scalars() if matches(rule, r)]
    anchor = await _anchor(session, rule, -1) or (records[0] if records else None)
    for record in records:
        if record.auto_status is None:
            record.auto_status = record.status
        record.status = AlertStatus.SUPPRESSED
        record.suppression_rule_id = rule.id
        record.review_reason = _note(rule)
        if record is not anchor:
            join_group(record, anchor)
    rule.hit_count += len(records)
    if records:
        rule.last_hit_at = datetime.utcnow()
    return records


async def create_rules(
    session: AsyncSession,
    refs_records: list[AlertRecord],
    scope: str,
    user: User,
    *,
    reason: str | None,
    duration_hours: int | None,
    apply_existing: bool,
) -> tuple[list[SuppressionRule], list[AlertRecord]]:
    # Hatokoronkent egy szabaly a kijelolt riasztasokbol; azonos elo szabaly ujrahasznalva.
    if scope not in SCOPES:
        raise SuppressionError(422, f"unknown scope: {scope}")
    keys: dict[tuple, AlertRecord] = {}
    for record in refs_records:
        keys.setdefault(_key(record, scope), record)

    expires_at = datetime.utcnow() + timedelta(hours=duration_hours) if duration_hours else None
    rules: list[SuppressionRule] = []
    for (fingerprint, rule_id, agent_name), sample in keys.items():
        existing = await session.execute(
            select(SuppressionRule).where(
                *_live(),
                SuppressionRule.scope == scope,
                SuppressionRule.fingerprint == fingerprint if fingerprint else SuppressionRule.fingerprint.is_(None),
                SuppressionRule.rule_id == rule_id if rule_id else SuppressionRule.rule_id.is_(None),
                SuppressionRule.agent_name == agent_name if agent_name else SuppressionRule.agent_name.is_(None),
            )
        )
        rule = existing.scalars().first()
        if rule is None:
            rule = SuppressionRule(
                scope=scope,
                fingerprint=fingerprint,
                rule_id=rule_id,
                agent_name=agent_name,
                description=sample.rule_description,
                reason=reason,
                created_by_id=user.id,
                expires_at=expires_at,
                hit_count=0,
            )
            session.add(rule)
            await session.flush()
        rules.append(rule)

    suppressed: list[AlertRecord] = []
    if apply_existing:
        for rule in rules:
            suppressed += await _suppress_existing(session, rule)
    await session.commit()
    logger.info("%s added %d suppression rule(s) (%s), %d existing alert(s) suppressed",
                user.username, len(rules), scope, len(suppressed))
    return rules, suppressed


async def list_rules(session: AsyncSession, include_inactive: bool = False) -> list[SuppressionRule]:
    stmt = select(SuppressionRule).order_by(SuppressionRule.created_at.desc())
    if not include_inactive:
        stmt = stmt.where(*_live())
    return list((await session.execute(stmt)).scalars())


async def deactivate_rule(session: AsyncSession, rule_id: int, user: User) -> SuppressionRule:
    # Csak kikapcsolas, a korabbi talalatok hivatkozasa megmarad.
    rule = await session.get(SuppressionRule, rule_id)
    if rule is None:
        raise SuppressionError(404, "suppression rule not found")
    rule.is_active = False
    await session.commit()
    logger.info("%s deactivated suppression rule #%s", user.username, rule.id)
    return rule
