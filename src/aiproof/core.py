"""Guard: the object that ties policy, ledger, redaction, filters and quotas.

Lifecycle of one model call::

    call = guard.before(provider, op, model, request)   # quotas + input filters
    ...  # the actual model call
    guard.after(call, response, usage)                  # output filters + ledger record

``Guard`` never raises out of ``before``/``after`` unless the policy says so
(``fail_closed``, ``on_injection="block"``, quotas). Internal errors are
recorded as ``event="aiproof.error"`` and the host application continues.
"""
from __future__ import annotations

import hashlib
import json
import time
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ._meta import NAME
from .config import Policy, load_policy
from .filters import FilterFinding, max_severity, run_input_filters, run_output_filters
from .ledger import Ledger, canonical
from .quota import QuotaExceeded, tracker
from .redact import redact_obj


class Blocked(PermissionError):
    """Raised when policy blocks a request or a response."""

    def __init__(self, reason: str, findings: List[FilterFinding]):
        super().__init__(reason)
        self.reason = reason
        self.findings = findings


@dataclass
class Call:
    id: str
    provider: str
    op: str
    model: str
    request: Any
    started: float
    input_findings: List[FilterFinding] = field(default_factory=list)
    pii: Dict[str, int] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)


def _to_plain(obj: Any, depth: int = 0) -> Any:
    """Best-effort conversion of SDK objects (pydantic etc.) to JSON-able data."""
    if depth > 12:
        return str(obj)
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, bytes):
        return f"<bytes:{len(obj)}>"
    if isinstance(obj, dict):
        return {str(k): _to_plain(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_plain(v, depth + 1) for v in obj]
    for meth in ("model_dump", "to_dict", "dict"):
        fn = getattr(obj, meth, None)
        if callable(fn):
            try:
                return _to_plain(fn(), depth + 1)
            except Exception:
                pass
    if hasattr(obj, "__dict__"):
        try:
            return {k: _to_plain(v, depth + 1) for k, v in vars(obj).items() if not k.startswith("_")}
        except Exception:
            pass
    return str(obj)


def _prompt_chars(obj: Any) -> int:
    if isinstance(obj, str):
        return len(obj)
    if isinstance(obj, dict):
        return sum(_prompt_chars(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return sum(_prompt_chars(v) for v in obj)
    return 0


def extract_text(response: Any) -> str:
    """Pull the assistant text out of OpenAI / Anthropic / generic responses."""
    r = response
    try:
        if isinstance(r, str):
            return r
        # OpenAI responses API
        t = getattr(r, "output_text", None)
        if isinstance(t, str) and t:
            return t
        d = _to_plain(r)
        if isinstance(d, dict):
            if isinstance(d.get("output_text"), str):
                return d["output_text"]
            ch = d.get("choices")
            if isinstance(ch, list) and ch:
                msg = ch[0].get("message") or {}
                parts = []
                if isinstance(msg.get("content"), str):
                    parts.append(msg["content"])
                for tc in msg.get("tool_calls") or []:
                    fn = (tc or {}).get("function") or {}
                    parts.append(f"[tool_call {fn.get('name')}] {fn.get('arguments', '')}")
                if ch[0].get("text"):
                    parts.append(ch[0]["text"])
                return "\n".join(p for p in parts if p)
            content = d.get("content")  # anthropic
            if isinstance(content, list):
                parts = []
                for b in content:
                    if isinstance(b, dict):
                        if b.get("type") == "text":
                            parts.append(b.get("text", ""))
                        elif b.get("type") == "tool_use":
                            parts.append(f"[tool_use {b.get('name')}] {json.dumps(b.get('input'), ensure_ascii=False)}")
                return "\n".join(parts)
            if isinstance(content, str):
                return content
            out = d.get("output")  # responses API raw
            if isinstance(out, list):
                parts = []
                for item in out:
                    for c in (item or {}).get("content") or []:
                        if isinstance(c, dict) and isinstance(c.get("text"), str):
                            parts.append(c["text"])
                return "\n".join(parts)
        return ""
    except Exception:
        return ""


def extract_usage(response: Any) -> Dict[str, int]:
    d = _to_plain(response)
    u = d.get("usage") if isinstance(d, dict) else None
    if not isinstance(u, dict):
        return {}
    out: Dict[str, int] = {}
    for src, dst in (
        ("prompt_tokens", "input"), ("input_tokens", "input"),
        ("completion_tokens", "output"), ("output_tokens", "output"),
        ("total_tokens", "total"),
    ):
        v = u.get(src)
        if isinstance(v, int):
            out[dst] = v
    if "total" not in out and ("input" in out or "output" in out):
        out["total"] = out.get("input", 0) + out.get("output", 0)
    return out


class Guard:
    def __init__(self, policy: Any = None):
        self.policy: Policy = load_policy(policy)
        self.ledger = Ledger(self.policy.ledger_path, key=self.policy.hmac_key(), app=self.policy.app,
                             rotate_mb=self.policy.rotate_mb)
        self._quota = tracker()

    # ------------------------------------------------------------------ util
    def _content_view(self, obj: Any) -> Dict[str, Any]:
        """Return {"sha256": ..., "data": ...} according to store_content."""
        plain = _to_plain(obj)
        digest = hashlib.sha256(canonical(plain)).hexdigest()
        view: Dict[str, Any] = {"sha256": digest}
        mode = self.policy.store_content
        if mode == "none":
            return view
        if mode == "hash":
            return view
        data = plain
        pii: Dict[str, int] = {}
        if self.policy.redact:
            data, findings = redact_obj(plain, self.policy.redact_types)
            for f in findings:
                pii[f.type] = pii.get(f.type, 0) + 1
        text = json.dumps(data, ensure_ascii=False)
        if len(text) > self.policy.max_content_chars:
            view["truncated"] = True
            data = text[: self.policy.max_content_chars]
        view["data"] = data
        if pii:
            view["pii"] = pii
        return view

    def _safe_append(self, event: str, payload: Dict[str, Any]) -> None:
        try:
            self.ledger.append(event, payload)
        except Exception as e:
            if self.policy.fail_closed:
                raise
            # last resort: stderr, never crash the app
            import sys
            print(f"[{NAME}] ledger write failed: {e}", file=sys.stderr)

    # ------------------------------------------------------------------ phases
    def before(self, provider: str, op: str, model: str, request: Any, **extra: Any) -> Call:
        call = Call(uuid.uuid4().hex, provider, op, model or "", request, time.time(), extra=extra)
        if not self.policy.enabled:
            return call
        try:
            plain = _to_plain(request)
            self._quota.check_request(
                self.policy.max_requests_per_minute, _prompt_chars(plain), self.policy.max_prompt_chars
            )
            self._quota.check_tokens(self.policy.max_tokens_per_day)
            if self.policy.filter_input:
                call.input_findings = run_input_filters(plain)
            sev = max_severity(call.input_findings)
            if self.policy.on_injection == "block" and sev in ("high", "critical"):
                self._write(call, None, {}, status="blocked", error=f"input blocked: {sev}")
                raise Blocked(f"input blocked by policy ({sev})", call.input_findings)
        except (Blocked, QuotaExceeded) as e:
            if isinstance(e, QuotaExceeded):
                self._write(call, None, {}, status="blocked", error=str(e))
            raise
        except Exception as e:
            self._internal_error("before", e)
            if self.policy.fail_closed:
                raise
        return call

    def after(self, call: Call, response: Any = None, usage: Optional[Dict[str, int]] = None,
              error: Optional[BaseException] = None, output_text: Optional[str] = None) -> None:
        if not self.policy.enabled:
            return
        try:
            if error is not None:
                self._write(call, None, {}, status="error", error=f"{type(error).__name__}: {error}"[:500])
                return
            text = output_text if output_text is not None else extract_text(response)
            usage = dict(usage) if usage else extract_usage(response)
            if usage and "total" not in usage and ("input" in usage or "output" in usage):
                usage["total"] = int(usage.get("input", 0)) + int(usage.get("output", 0))
            out_findings: List[FilterFinding] = []
            if self.policy.filter_output:
                out_findings = run_output_filters(text)
            if usage.get("total"):
                total, over = self._quota.add_tokens(usage["total"], self.policy.max_tokens_per_day)
                if over:
                    out_findings.append(FilterFinding("quota.tokens_per_day", "medium", "quota", f"{total} tokens today"))
            self._write(call, response, usage, status="ok", output_findings=out_findings, output_text=text)
            if self.policy.on_secret_leak == "block" and any(f.category == "secret" for f in out_findings):
                raise Blocked("output blocked by policy (secret leak)", out_findings)
        except Blocked:
            raise
        except Exception as e:
            self._internal_error("after", e)
            if self.policy.fail_closed:
                raise

    # ------------------------------------------------------------------ writing
    def _write(self, call: Call, response: Any, usage: Dict[str, int], status: str,
               error: Optional[str] = None, output_findings: Optional[List[FilterFinding]] = None,
               output_text: Optional[str] = None) -> None:
        payload: Dict[str, Any] = {
            "call_id": call.id,
            "provider": call.provider,
            "op": call.op,
            "model": call.model,
            "status": status,
            "latency_ms": int((time.time() - call.started) * 1000),
            "policy": self.policy.name,
            "request": self._content_view(call.request),
        }
        if self.policy.tags:
            payload["tags"] = dict(self.policy.tags)
        if call.extra:
            payload["meta"] = {k: v for k, v in call.extra.items() if isinstance(v, (str, int, float, bool))}
        if status == "ok":
            payload["response"] = self._content_view(output_text if output_text is not None else response)
            if usage:
                payload["usage"] = usage
        if error:
            payload["error"] = error
        findings: Dict[str, Any] = {}
        if call.input_findings:
            findings["input"] = [f.to_dict() for f in call.input_findings]
        if output_findings:
            findings["output"] = [f.to_dict() for f in output_findings]
        if findings:
            payload["findings"] = findings
            payload["severity"] = max_severity(call.input_findings + (output_findings or []))
        self._safe_append("llm.call", payload)

    def _internal_error(self, phase: str, e: BaseException) -> None:
        self._safe_append(f"{NAME}.error", {
            "phase": phase,
            "error": f"{type(e).__name__}: {e}"[:300],
            "trace": traceback.format_exc()[-1500:],
        })

    def event(self, event: str, **payload: Any) -> None:
        """Write an arbitrary application event (tool call, approval, deploy...)."""
        self._safe_append(event, _to_plain(payload))
