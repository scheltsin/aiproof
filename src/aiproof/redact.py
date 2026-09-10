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
from functools import lru_cache
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple

from ._meta import ENV_PREFIX

Validator = Callable[[str], bool]


@dataclass
class Detector:
    name: str
    pattern: Pattern[str]
    validator: Optional[Validator] = None
    # group index that holds the value to validate/replace (0 = whole match)
    group: int = 0
    # cheap pre-check run before the main pattern: "digit" (text has a digit), "cyr" (has a capital
    # Cyrillic letter), a compiled regex, or None (always run)
    prefilter: Any = "digit"


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


# ------------------------------------------------------------------ more validators

def valid_okpo(value: str) -> bool:
    d = _digits(value)
    if len(d) not in (8, 10) or _trivial(d):
        return False
    n = len(d) - 1

    def chk(shift: int) -> int:
        w = [((i + shift - 1) % 10) + 1 for i in range(1, n + 1)]
        return sum(int(d[i]) * w[i] for i in range(n)) % 11

    c = chk(0)
    if c == 10:
        c = chk(2)
        if c == 10:
            c = 0
    return c == int(d[n])


def valid_bik(value: str) -> bool:
    d = _digits(value)
    return len(d) == 9 and d[:2] == "04" and not _trivial(d)


def valid_iban(value: str) -> bool:
    v = re.sub(r"\s", "", value).upper()
    if not 15 <= len(v) <= 34 or not v[:2].isalpha():
        return False
    moved = v[4:] + v[:4]
    num = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in moved)
    return int(num) % 97 == 1


def valid_vin(value: str) -> bool:
    v = value.upper()
    return len(v) == 17 and any(c.isdigit() for c in v) and any(c.isalpha() for c in v) and not _trivial(v)


def valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts) and value not in ("0.0.0.0", "127.0.0.1")


def valid_date(value: str) -> bool:
    m = re.match(r"(\d{2})[./-](\d{2})[./-](\d{4})", value)
    if not m:
        return False
    dd, mm, yyyy = int(m.group(1)), int(m.group(2)), int(m.group(3))
    return 1 <= dd <= 31 and 1 <= mm <= 12 and 1900 <= yyyy <= 2100


# ------------------------------------------------------------------ detectors

_CTX_PASSPORT = r"(?:паспорт\w*|серия|сер\.|№|номер|passport)[^\d\n]{0,20}"
_CTX_DL = r"(?:в/у|ву|водительск\w+\s+удостоверени\w+|прав[а-я]*\s+(?:серия|№|номер)|driver'?s?\s+licen[cs]e)[^\d\n]{0,20}"
_CTX_INTL = r"(?:загранпаспорт\w*|заграничн\w+\s+паспорт\w*|загран)[^\d\n]{0,20}"
_CTX_OMS = r"(?:полис\w*|омс|oms)[^\d\n]{0,20}"
_CTX_KPP = r"(?:кпп|kpp)[^\d\n]{0,10}"
_CTX_OKPO = r"(?:окпо|okpo)[^\d\n]{0,10}"
_CTX_BIRTH = r"(?:дата\s+рождения|д\.\s?р\.|родил[ас]я|день\s+рождения|date\s+of\s+birth|dob|birthday)[^\d\n]{0,15}"
_CTX_CVV = r"(?:cvv|cvc|cvv2|cvc2|код\s+безопасности)[^\d\n]{0,6}"
_CTX_BIRTH_CERT = r"(?:свидетельств\w+\s+о\s+рождении|св-во\s+о\s+рождении)[^\n]{0,20}?"

_CYR_WORD = r"[А-ЯЁ][а-яё]+(?:-[А-ЯЁ][а-яё]+)?"
_PATRONYMIC = r"[А-ЯЁ][а-яё]+(?:ович|евич|ьич|ична|инична|овна|евна)"

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
    ), prefilter=re.compile(r"-----BEGIN|sk-|AKIA|gh[pousr]_|xox[baprs]-|glpat-|AIza|eyJ|(?i:key|token|secret|password|пароль)")),
    # people
    Detector("fio", re.compile(
        rf"(?<![А-ЯЁа-яё])(?:{_CYR_WORD}[ \t]+{_CYR_WORD}[ \t]+{_PATRONYMIC}"   # Иванов Иван Иванович
        rf"|{_CYR_WORD}[ \t]+{_PATRONYMIC}[ \t]+{_CYR_WORD}"                    # Иван Иванович Иванов
        rf"|{_CYR_WORD}[ \t]+[А-ЯЁ]\.[ \t]?[А-ЯЁ]\."                            # Иванов И.И.
        rf"|[А-ЯЁ]\.[ \t]?[А-ЯЁ]\.[ \t]?{_CYR_WORD})(?![А-ЯЁа-яё])"), prefilter="cyr"),  # И.И. Иванов
    Detector("address", re.compile(
        r"(?:(?:г\.|город|с\.|село|пос\.|посёлок|поселок|д\.|деревня)\s*[А-ЯЁ][а-яё\-]+(?:\s[А-ЯЁ][а-яё\-]+)?,?\s*)?"
        r"(?:ул\.|улица|просп\.|пр-т|проспект|пер\.|переулок|ш\.|шоссе|наб\.|набережная|бул\.|бульвар|пл\.|площадь|пр-д|проезд)"
        r"\s*[А-ЯЁа-яё0-9 .\-]{2,40}?,?\s*(?:д\.|дом)\s*\d+[а-я]?(?:\s*/\s*\d+)?"
        r"(?:,?\s*(?:к\.|корп\.|корпус|стр\.|строение)\s*\d+[а-я]?)*"
        r"(?:,?\s*(?:кв\.|квартира|оф\.|офис|пом\.|помещение)\s*\d+[а-я]?)?", re.IGNORECASE),
        prefilter=re.compile(r"(?i)ул\.|улица|просп|пр-т|пер\.|переулок|шоссе|наб\.|бул|пл\.|площадь|проезд|пр-д|ш\.")),
    Detector("birth_date", re.compile(_CTX_BIRTH + r"(\d{2}[./-]\d{2}[./-]\d{4})(?!\d)", re.IGNORECASE), valid_date, 1),
    # documents (context-anchored)
    Detector("passport_rf", re.compile(_CTX_PASSPORT + r"(\d{2}\s?\d{2}\s?\d{6})(?!\d)", re.IGNORECASE), None, 1),
    Detector("intl_passport", re.compile(_CTX_INTL + r"(\d{2}\s?\d{7})(?!\d)", re.IGNORECASE), None, 1),
    Detector("driver_license", re.compile(_CTX_DL + r"(\d{2}\s?[0-9А-ЯЁ]{2}\s?\d{6})(?![\dА-ЯЁ])", re.IGNORECASE), None, 1),
    Detector("birth_cert", re.compile(_CTX_BIRTH_CERT + r"([IVX]{1,4}\s?-\s?[А-ЯЁ]{2}\s*№?\s*\d{6})", re.IGNORECASE), None, 1),
    Detector("oms", re.compile(_CTX_OMS + r"((?:\d[ \-]?){16})(?!\d)", re.IGNORECASE), valid_luhn, 1),
    Detector("kpp", re.compile(_CTX_KPP + r"(\d{4}[0-9A-Z]{2}\d{3})(?!\d)", re.IGNORECASE), None, 1),
    Detector("cvv", re.compile(_CTX_CVV + r"(\d{3,4})(?!\d)", re.IGNORECASE), None, 1),
    # checksum-validated identifiers
    Detector("snils", re.compile(r"(?<!\d)\d{3}[ \-]?\d{3}[ \-]?\d{3}[ \-]?\d{2}(?!\d)"), valid_snils),
    Detector("bank_account", re.compile(r"(?<!\d)\d{20}(?!\d)"), valid_bank_account),
    Detector("ogrn", re.compile(r"(?<!\d)\d{13}(?:\d{2})?(?!\d)"), valid_ogrn),
    Detector("inn", re.compile(r"(?<!\d)\d{10}(?:\d{2})?(?!\d)"), valid_inn),
    Detector("okpo", re.compile(_CTX_OKPO + r"(\d{8}(?:\d{2})?)(?!\d)", re.IGNORECASE), valid_okpo, 1),
    Detector("bik", re.compile(r"(?<!\d)04\d{7}(?!\d)"), valid_bik),
    Detector("card", re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)"), valid_luhn),
    Detector("iban", re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}\s?[A-Z0-9]{1,4}\b"), valid_iban,
             prefilter=re.compile(r"\b[A-Z]{2}\d{2}")),
    # property / vehicles
    Detector("cadastral", re.compile(r"(?<![\d:])\d{2}:\d{2}:\d{6,7}:\d{1,5}(?![\d:])")),
    Detector("vehicle_plate", re.compile(r"(?<![А-ЯЁA-Z0-9])[АВЕКМНОРСТУХ]\s?\d{3}\s?[АВЕКМНОРСТУХ]{2}\s?\d{2,3}(?![А-ЯЁA-Z0-9])")),
    Detector("vin", re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), valid_vin),
    # contacts / network
    Detector("phone_ru", re.compile(r"(?<![\d\w])(?:\+7|8)[ \-]?\(?\d{3}\)?[ \-]?\d{3}[ \-]?\d{2}[ \-]?\d{2}(?!\d)"), valid_phone_ru),
    Detector("email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), prefilter=re.compile("@")),
    Detector("ipv4", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"), valid_ipv4),
]

ALL_TYPES: List[str] = [d.name for d in DETECTORS]

_BY_NAME: Dict[str, Detector] = {d.name: d for d in DETECTORS}


def register(name: str, pattern: str, validator: Optional[Validator] = None, group: int = 0) -> None:
    """Add or replace a detector at runtime."""
    det = Detector(name, re.compile(pattern), validator, group, prefilter=None)
    _BY_NAME[name] = det
    _redact_cached.cache_clear()
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


_HAS_DIGIT = re.compile(r"\d")
_HAS_CYR_CAP = re.compile(r"[А-ЯЁ]")


def _passes_prefilter(det: Detector, text: str, has_digit: bool, has_cyr: bool) -> bool:
    pf = det.prefilter
    if pf is None:
        return True
    if pf == "digit":
        return has_digit
    if pf == "cyr":
        return has_cyr
    return pf.search(text) is not None


def redact(text: str, types: Optional[List[str]] = None) -> Tuple[str, List[Finding]]:
    """Return (redacted_text, findings). ``types`` restricts detector names."""
    if not text or not isinstance(text, str):
        return text, []
    if types is not None and "*" in types:
        types = None
    out, findings = _redact_cached(text, tuple(types) if types is not None else None)
    return out, list(findings)


@lru_cache(maxsize=256)
def _redact_cached(text: str, types: Optional[Tuple[str, ...]]) -> Tuple[str, Tuple[Finding, ...]]:
    active = [d for d in DETECTORS if types is None or d.name in types]
    has_digit = _HAS_DIGIT.search(text) is not None
    has_cyr = _HAS_CYR_CAP.search(text) is not None
    spans: List[Tuple[int, int, str, str]] = []  # start, end, kind, token
    taken: List[Tuple[int, int]] = []

    def overlaps(a: int, b: int) -> bool:
        return any(a < e and b > s for s, e in taken)

    for det in active:
        if not _passes_prefilter(det, text, has_digit, has_cyr):
            continue
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
        return text, ()
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
    return "".join(out), tuple(findings)


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
