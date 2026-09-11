"""Input / output filters: prompt-injection heuristics (RU + EN), hidden
content (zero-width / bidi unicode, HTML comments), secret leakage.

These are explainable rules, not a classifier. The goal is an auditable,
deterministic first line and a hook point (``add_input_filter`` /
``add_output_filter``) where a company can plug its own gateway or model.
Every finding is written to the ledger; blocking is a policy decision.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List

from . import redact as _redact


@dataclass
class FilterFinding:
    rule: str
    severity: str  # low | medium | high | critical
    category: str  # injection | hidden | exfiltration | secret | dangerous
    snippet: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


_R = re.IGNORECASE | re.UNICODE

INJECTION_RULES = [
    # override / hierarchy
    ("inj.override.en", "high", r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)"),
    ("inj.override.ru", "high", r"(игнорируй|проигнорируй|забудь|отбрось)\s+(все\s+)?(предыдущие|прежние|вышеуказанные|прошлые)\s+(инструкции|указания|правила|промпты?)"),
    ("inj.sysprompt.en", "high", r"\b(system\s+prompt|developer\s+message)\b.*\b(ignore|override|replace|reveal|print|show)\b|\b(reveal|print|show|repeat)\b.*\b(system\s+prompt|your\s+instructions)"),
    ("inj.sysprompt.ru", "high", r"(покажи|выведи|напечатай|раскрой|повтори)\s+.*(системн\w+\s+промпт|свои\s+инструкции|исходные\s+указания)"),
    ("inj.newrole.en", "medium", r"\byou\s+are\s+now\b|\bfrom\s+now\s+on\s+you\b|\bact\s+as\s+(an?\s+)?(unrestricted|jailbroken|dan)\b"),
    ("inj.newrole.ru", "medium", r"\bтеперь\s+ты\b|\bотныне\s+ты\b|\bпритворись,?\s+что\s+(у\s+тебя\s+нет|ты\s+без)\s+ограничени"),
    ("inj.stealth.en", "high", r"\bdo\s+not\s+(mention|tell|reveal|disclose)\b.*\b(user|this|action|step)\b|\bwithout\s+telling\s+the\s+user\b"),
    ("inj.stealth.ru", "high", r"\bне\s+(сообщай|говори|упоминай|показывай)\s+(об\s+этом\s+)?пользователю\b|\bскрытно\s+от\s+пользователя\b"),
    ("inj.disable.en", "high", r"\b(disable|bypass|turn\s+off|skip)\s+(the\s+)?(safety|guardrails?|filters?|approval|sandbox|review|checks?)\b"),
    ("inj.disable.ru", "high", r"\b(отключи|обойди|выключи|пропусти)\s+(проверк|защит|фильтр|ограничен|подтвержден|песочниц)"),
    ("inj.urgency.en", "low", r"\bthis\s+is\s+an?\s+(urgent|emergency)\s+(security|admin)\b"),
    # exfiltration / dangerous
    ("exfil.secrets.en", "critical", r"\b(read|cat|print|send|upload|exfiltrate)\b.*(~/\.ssh|~/\.aws|\.env\b|id_rsa|credentials|api[_\s-]?keys?|tokens?)\b"),
    ("exfil.secrets.ru", "critical", r"\b(прочитай|отправь|выгрузи|скопируй|перешли)\b.*(\.env\b|ssh|ключ[аи]?\s+api|токен|пароли|учетн\w+\s+данн)"),
    ("exfil.network", "high", r"\b(curl|wget|nc|ncat|Invoke-WebRequest)\b.*\b(https?://|\$\(|\|\s*(ba)?sh)\b"),
    ("danger.shell", "critical", r"\brm\s+-rf\s+/|\bsudo\s+rm\b|\bgit\s+push\s+--force\b|\bmkfs\.|\bdd\s+if=|\bchmod\s+-R\s+777\b"),
    ("danger.agentcfg", "medium", r"\b(edit|modify|overwrite|replace|измени|перепиши)\b.*\b(AGENTS\.md|CLAUDE\.md|\.cursorrules|copilot-instructions\.md|SKILL\.md)\b"),
]

_INJ = [(rid, sev, re.compile(rx, _R)) for rid, sev, rx in INJECTION_RULES]

_ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿­]")
_BIDI = re.compile(r"[‪-‮⁦-⁩]")
_HTML_COMMENT = re.compile(r"<!--[\s\S]{8,}?-->")
_TAG_INSTR = re.compile(r"\[/?(INST|SYS|SYSTEM)\]|<\|?(im_start|im_end|system|endoftext)\|?>", _R)


def _snippet(text: str, start: int, end: int, width: int = 60) -> str:
    s = max(0, start - 20)
    e = min(len(text), end + 20)
    return text[s:e].replace("\n", " ")[:width * 2]


def scan_text(text: str) -> List[FilterFinding]:
    """Return findings for a single string."""
    out: List[FilterFinding] = []
    if not text or not isinstance(text, str):
        return out
    for rid, sev, rx in _INJ:
        m = rx.search(text)
        if m:
            cat = rid.split(".")[0]
            cat = {"inj": "injection", "exfil": "exfiltration", "danger": "dangerous"}.get(cat, cat)
            out.append(FilterFinding(rid, sev, cat, _snippet(text, *m.span())))
    n_zw = len(_ZERO_WIDTH.findall(text))
    if n_zw >= 3:
        out.append(FilterFinding("hidden.zero_width", "high", "hidden", f"{n_zw} zero-width chars"))
    if _BIDI.search(text):
        out.append(FilterFinding("hidden.bidi", "high", "hidden", "bidirectional override chars"))
    m = _HTML_COMMENT.search(text)
    if m:
        out.append(FilterFinding("hidden.html_comment", "medium", "hidden", _snippet(text, *m.span())))
    m = _TAG_INSTR.search(text)
    if m:
        out.append(FilterFinding("inj.fake_delimiters", "medium", "injection", _snippet(text, *m.span())))
    return out


def scan_obj(obj: Any) -> List[FilterFinding]:
    """Scan every string in a nested structure (messages, tool calls...)."""
    out: List[FilterFinding] = []
    if isinstance(obj, str):
        return scan_text(obj)
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(scan_obj(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(scan_obj(v))
    return out


def scan_output_secrets(text: str) -> List[FilterFinding]:
    """Detect secrets / PII in model output (leak of context or training data)."""
    out: List[FilterFinding] = []
    if not isinstance(text, str):
        return out
    _, findings = _redact.redact(text)
    kinds: Dict[str, int] = {}
    for f in findings:
        kinds[f.type] = kinds.get(f.type, 0) + 1
    for kind, n in kinds.items():
        if kind == "secret":
            out.append(FilterFinding("leak.secret", "critical", "secret", f"{n} x secret in output"))
        else:
            out.append(FilterFinding(f"leak.{kind}", "medium", "pii", f"{n} x {kind} in output"))
    return out


# ------------------------------------------------------------------ hooks

InputFilter = Callable[[Any], List[FilterFinding]]
OutputFilter = Callable[[str], List[FilterFinding]]

_input_filters: List[InputFilter] = [scan_obj]
_output_filters: List[OutputFilter] = [scan_output_secrets]


def add_input_filter(fn: InputFilter) -> None:
    """Register a custom input filter: fn(request_dict) -> [FilterFinding]."""
    _input_filters.append(fn)


def add_output_filter(fn: OutputFilter) -> None:
    """Register a custom output filter: fn(output_text) -> [FilterFinding]."""
    _output_filters.append(fn)


def run_input_filters(request: Any) -> List[FilterFinding]:
    out: List[FilterFinding] = []
    for fn in _input_filters:
        try:
            out.extend(fn(request) or [])
        except Exception as e:  # a broken custom filter must not kill the request
            out.append(FilterFinding("filter.error", "low", "internal", f"{type(e).__name__}: {e}"[:120]))
    return out


def run_output_filters(text: str) -> List[FilterFinding]:
    out: List[FilterFinding] = []
    for fn in _output_filters:
        try:
            out.extend(fn(text) or [])
        except Exception as e:
            out.append(FilterFinding("filter.error", "low", "internal", f"{type(e).__name__}: {e}"[:120]))
    return out


def max_severity(findings: List[FilterFinding]) -> str:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    best = -1
    for f in findings:
        best = max(best, order.get(f.severity, 0))
    return ["none", "low", "medium", "high", "critical"][best + 1]
