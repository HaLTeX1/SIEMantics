# Futasi allapot a Rendszerallapot fulhoz: az LLM es a szinkronok legutobbi esemenyei (memoriaban, ujrainditaskor ures).

from datetime import datetime

_state: dict[str, dict] = {}


def record_success(name: str, info: dict | None = None) -> None:
    entry = _state.setdefault(name, {})
    entry.update(last_success_at=datetime.utcnow(), last_result=info or {})


def record_failure(name: str, error: Exception | str, **extra) -> None:
    entry = _state.setdefault(name, {})
    entry.update(last_error_at=datetime.utcnow(), last_error=str(error)[:500], **extra)


def snapshot(name: str) -> dict:
    return dict(_state.get(name, {}))


def reset() -> None:
    _state.clear()
