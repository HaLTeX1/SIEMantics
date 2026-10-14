import hashlib
import re

# Ujjlenyomat: host + szabaly + kulcsmezok, a valtozo reszek (verzio, hash, GUID, szam) nelkul.
_IP_KEYS = ("srcip", "src_ip", "dstip", "dest_ip")
_TEXT_KEYS = (
    "win.eventdata.commandLine",
    "win.eventdata.image",
    "win.eventdata.targetFilename",
    "dstuser",
    "url",
    "alert.signature",
    "vulnerability.cve",
    "vulnerability.package.name",
)
_NORMALIZE = [
    (re.compile(r"\{?[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?"), "<guid>"),
    (re.compile(r"\b\d+(\.\d+)+\b"), "<ver>"),
    (re.compile(r"\b[0-9a-fA-F]{6,}\b"), "<hex>"),
    (re.compile(r"\d+"), "<n>"),
]


def _dig(data: dict, path: str):
    for key in path.split("."):
        data = data.get(key) if isinstance(data, dict) else None
    return data


def normalize(value) -> str:
    text = str(value)
    for pattern, placeholder in _NORMALIZE:
        text = pattern.sub(placeholder, text)
    return text.lower()


def alert_fingerprint(raw: dict | None) -> str | None:
    raw = raw or {}
    rule_id = (raw.get("rule") or {}).get("id")
    if not rule_id:
        return None
    data = raw.get("data") or {}
    parts = [(raw.get("agent") or {}).get("name") or "-", str(rule_id)]
    # Az IP-k valtozatlanul: mas forras mas riasztas.
    parts += [f"{key}={_dig(data, key)}" for key in _IP_KEYS if _dig(data, key)]
    parts += [f"{key}={normalize(_dig(data, key))}" for key in _TEXT_KEYS if _dig(data, key)]
    path = (raw.get("syscheck") or {}).get("path")
    if path:
        parts.append(f"path={normalize(path)}")
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
