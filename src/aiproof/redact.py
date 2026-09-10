"""PII / secret redaction with Russian-specific detectors.

Detectors validate checksums where the identifier has one (ИНН, СНИЛС, ОГРН,
ОГРНИП, bank cards via Luhn) to keep false positives low. Each match is
replaced by a stable token ``<TYPE:xxxx>`` where ``xxxx`` is the first 4 hex
chars of SHA-256(salt + value), so the same value maps to the same token inside
one process (useful for reading logs) without storing the value.

Stdlib only, no ML. Add your own detector with ``register(name, regex, validator)``.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Pattern, Tuple

from ._meta import ENV_PREFIX

Validator = Callable[[str], bool]


@dataclass
class Detector:
    name: str
    pattern: Pattern[str]
    validator: Optional[Validator] = None
    # group index that holds the value to validate/replace (0 = whole match)
    group: int = 0


@dataclass
class Finding:
    type: str
    token: str
    start: int
    end: int


# ------------------------------------------------------------------ validators

def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _trivial(d: str) -> bool:
    return len(set(d)) <= 1  # 0000000000 and the like pass checksums but are not real ids


def valid_inn(value: str) -> bool:
    d = _digits(value)
    if _trivial(d):
        return False
    if len(d) == 10:
        w = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        c = sum(int(d[i]) * w[i] for i in range(9)) % 11 % 10
        return c == int(d[9])
    if len(d) == 12:
        w11 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        w12 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        c11 = sum(int(d[i]) * w11[i] for i in range(10)) % 11 % 10
        c12 = sum(int(d[i]) * w12[i] for i in range(11)) % 11 % 10
        return c11 == int(d[10]) and c12 == int(d[11])
    return False


def valid_snils(value: str) -> bool:
    d = _digits(value)
    if len(d) != 11 or _trivial(d):
        return False
    num, check = d[:9], int(d[9:])
    if int(num) <= 1001998:  # numbers below 001-001-998 are not checked
        return True
    s = sum(int(num[i]) * (9 - i) for i in range(9))
    if s < 100:
        c = s
    elif s in (100, 101):
        c = 0
    else:
        c = s % 101
        if c in (100, 101):
            c = 0
    return c == check


def valid_ogrn(value: str) -> bool:
    d = _digits(value)
    if _trivial(d):
        return False
    if len(d) == 13:
        return int(d[:12]) % 11 % 10 == int(d[12])
    if len(d) == 15:  # ОГРНИП
        return int(d[:14]) % 13 % 10 == int(d[14])
    return False


def valid_luhn(value: str) -> bool:
    d = _digits(value)
    if not 13 <= len(d) <= 19 or _trivial(d):
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def valid_phone_ru(value: str) -> bool:
    d = _digits(value)
    if len(d) == 11 and d[0] in "78":
        return d[1] in "3489"  # mobile 9xx, landline 3xx/4xx/8xx
    return False


def valid_bank_account(value: str) -> bool:
    d = _digits(value)
    # RU settlement accounts are 20 digits and start with a balance account 40x/42x/45x/47x/30x
    return len(d) == 20 and d[:2] in {"40", "42", "45", "47", "30", "20"}


# ------------------------------------------------------------------ detectors

_CTX_PASSPORT = r"(?:паспорт\w*|серия|сер\.|№|номер|passport)[^\d\n]{0,20}"

DETECTORS: List[Detector] = [
    Detector("secret", re.compile(
        r"(?:"
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        r"|sk-[A-Za-z0-9_\-]{20,}"          # OpenAI-style
        r"|sk-ant-[A-Za-z0-9_\-]{20,}"      # Anthropic
        r"|AKIA[0-9A-Z]{16}"                 # AWS
        r"|gh[pousr]_[A-Za-z0-9]{30,}"       # GitHub
        r"|xox[baprs]-[A-Za-z0-9\-]{10,}"    # Slack
        r"|glpat-[A-Za-z0-9_\-]{20,}"        # GitLab
        r"|(?:AIza)[0-9A-Za-z_\-]{30,}"      # Google
        r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"  # JWT
        r"|(?i:(?:api[_\-]?key|token|secret|password|пароль)\s*[:=]\s*['\"]?)[A-Za-z0-9_\-\.]{12,}"
        r")"
    )),
    Detector("snils", re.compile(r"(?<!\d)\d{3}[ \-]?\d{3}[ \-]?\d{3}[ \-]?\d{2}(?!\d)"), valid_snils),
    Detector("bank_account", re.compile(r"(?<!\d)\d{20}(?!\d)"), valid_bank_account),
    Detector("ogrn", re.compile(r"(?<!\d)\d{13}(?:\d{2})?(?!\d)"), valid_ogrn),
    Detector("inn", re.compile(r"(?<!\d)\d{10}(?:\d{2})?(?!\d)"), valid_inn),
    Detector("card", re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)"), valid_luhn),
    Detector("passport_rf", re.compile(_CTX_PASSPORT + r"(\d{2}\s?\d{2}\s?\d{6})(?!\d)", re.IGNORECASE), None, 1),
    Detector("phone_ru", re.compile(r"(?<![\d\w])(?:\+7|8)[ \-]?\(?\d{3}\)?[ \-]?\d{3}[ \-]?\d{2}[ \-]?\d{2}(?!\d)"), valid_phone_ru),
    Detector("email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
]

_BY_NAME: Dict[str, Detector] = {d.name: d for d in DETECTORS}


def register(name: str, pattern: str, validator: Optional[Validator] = None, group: int = 0) -> None:
    """Add or replace a detector at runtime."""
    det = Detector(name, re.compile(pattern), validator, group)
    _BY_NAME[name] = det
    for i, d in enumerate(DETECTORS):
        if d.name == name:
            DETECTORS[i] = det
            return
    DETECTORS.insert(0, det)


# ------------------------------------------------------------------ redaction

_SALT = os.environ.get(f"{ENV_PREFIX}_REDACT_SALT") or os.urandom(8).hex()


def token_for(kind: str, value: str) -> str:
    h = hashlib.sha256((_SALT + "|" + value).encode("utf-8")).hexdigest()[:4]
    return f"<{kind.upper()}:{h}>"


def redact(text: str, types: Optional[List[str]] = None) -> Tuple[str, List[Finding]]:
    """Return (redacted_text, findings). ``types`` restricts detector names."""
    if not text or not isinstance(text, str):
        return text, []
    active = [d for d in DETECTORS if types is None or d.name in types]
    spans: List[Tuple[int, int, str, str]] = []  # start, end, kind, token
    taken: List[Tuple[int, int]] = []

    def overlaps(a: int, b: int) -> bool:
        return any(a < e and b > s for s, e in taken)

    for det in active:
        for m in det.pattern.finditer(text):
            s, e = m.span(det.group)
            value = m.group(det.group)
            if det.validator and not det.validator(value):
                continue
            if overlaps(s, e):
                continue
            taken.append((s, e))
            spans.append((s, e, det.name, token_for(det.name, value)))

    if not spans:
        return text, []
    spans.sort()
    out: List[str] = []
    last = 0
    findings: List[Finding] = []
    for s, e, kind, tok in spans:
        out.append(text[last:s])
        out.append(tok)
        findings.append(Finding(kind, tok, s, e))
        last = e
    out.append(text[last:])
    return "".join(out), findings


def redact_obj(obj, types: Optional[List[str]] = None, _acc: Optional[List[Finding]] = None):
    """Recursively redact strings inside dicts/lists (messages, tool args, ...)."""
    acc = _acc if _acc is not None else []
    if isinstance(obj, str):
        r, f = redact(obj, types)
        acc.extend(f)
        return (r, acc) if _acc is None else r
    if isinstance(obj, dict):
        res = {k: redact_obj(v, types, acc) for k, v in obj.items()}
        return (res, acc) if _acc is None else res
    if isinstance(obj, (list, tuple)):
        res = [redact_obj(v, types, acc) for v in obj]
        return (res, acc) if _acc is None else res
    return (obj, acc) if _acc is None else obj
