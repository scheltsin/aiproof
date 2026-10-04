"""Exports: ledger records to SIEM / observability formats, findings to SARIF.

* ``otel``  – OpenTelemetry GenAI semantic conventions (``gen_ai.*`` attributes), one span per line
* ``ocsf``  – OCSF 1.x ``API Activity`` (class_uid 6003) events, one per line (Agent Control Standard
             recommends OTel + OCSF for agent observability)
* ``cef``   – ArcSight CEF lines for syslog collectors (KUMA, MaxPatrol SIEM, Splunk, QRadar)
* SARIF 2.1.0 for ``aiproof check`` findings (GitHub code scanning, GitLab SAST)
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Iterable, Iterator, List

from ._meta import NAME, VERSION

SEVERITY_NUM = {"none": 0, "low": 3, "medium": 5, "high": 8, "critical": 10}


def _iter_records(paths: Iterable[str]) -> Iterator[Dict[str, Any]]:
    for p in paths:
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except Exception:
                        continue


def _ts_ns(ts: str) -> int:
    try:
        base, frac = ts.rstrip("Z").split(".") if "." in ts else (ts.rstrip("Z"), "0")
        t = time.mktime(time.strptime(base, "%Y-%m-%dT%H:%M:%S")) - time.timezone
        return int(t * 1e9) + int(frac.ljust(9, "0")[:9])
    except Exception:
        return int(time.time() * 1e9)


# ------------------------------------------------------------------ OpenTelemetry GenAI

def to_otel(rec: Dict[str, Any]) -> Dict[str, Any]:
    end = _ts_ns(rec.get("ts", ""))
    start = end - int(rec.get("latency_ms", 0)) * 1_000_000
    event = rec.get("event", "")
    attrs: Dict[str, Any] = {
        "service.name": rec.get("app"),
        "aiproof.seq": rec.get("seq"),
        "aiproof.hash": rec.get("hash"),
        "aiproof.policy": rec.get("policy"),
        "aiproof.status": rec.get("status"),
    }
    if event == "llm.call":
        attrs.update({
            "gen_ai.operation.name": rec.get("op"),
            "gen_ai.system": rec.get("provider"),
            "gen_ai.request.model": rec.get("model"),
            "gen_ai.usage.input_tokens": (rec.get("usage") or {}).get("input"),
            "gen_ai.usage.output_tokens": (rec.get("usage") or {}).get("output"),
            "aiproof.request.sha256": (rec.get("request") or {}).get("sha256"),
            "aiproof.response.sha256": (rec.get("response") or {}).get("sha256"),
            "aiproof.pii": json.dumps((rec.get("request") or {}).get("pii") or {}),
        })
        name = f"{rec.get('op')} {rec.get('model')}"
    elif event == "tool.call":
        attrs.update({
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": rec.get("tool"),
            "gen_ai.agent.name": rec.get("agent"),
            "aiproof.decision": rec.get("decision"),
            "aiproof.approved_by": rec.get("approved_by"),
        })
        name = f"execute_tool {rec.get('tool')}"
    else:
        name = event
    if rec.get("severity"):
        attrs["aiproof.severity"] = rec["severity"]
    if rec.get("findings"):
        attrs["aiproof.findings"] = json.dumps(rec["findings"], ensure_ascii=False)
    if rec.get("error"):
        attrs["error.type"] = str(rec["error"]).split(":")[0]
    return {
        "name": name,
        "trace_id": (rec.get("hash") or "0" * 32)[:32],
        "span_id": (rec.get("hash") or "0" * 16)[:16],
        "start_time_unix_nano": start,
        "end_time_unix_nano": end,
        "status": {"code": "ERROR" if rec.get("status") in ("error", "blocked") else "OK"},
        "attributes": {k: v for k, v in attrs.items() if v is not None},
        "resource": {"service.name": rec.get("app"), "telemetry.sdk.name": NAME, "telemetry.sdk.version": VERSION},
    }


# ------------------------------------------------------------------ OCSF API Activity (6003)

def to_ocsf(rec: Dict[str, Any]) -> Dict[str, Any]:
    status = rec.get("status", "ok")
    sev = rec.get("severity", "none")
    sev_id = {"none": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}.get(sev, 1)
    event = rec.get("event", "")
    op = rec.get("tool") if event == "tool.call" else rec.get("op")
    return {
        "category_uid": 6, "category_name": "Application Activity",
        "class_uid": 6003, "class_name": "API Activity",
        "activity_id": 1, "activity_name": "Create",
        "type_uid": 600301,
        "time": _ts_ns(rec.get("ts", "")) // 1_000_000,
        "severity_id": sev_id, "severity": sev.capitalize(),
        "status_id": {"ok": 1, "error": 2, "blocked": 2}.get(status, 0), "status": status,
        "message": f"{event} {op} {rec.get('model') or ''}".strip(),
        "api": {"operation": op, "service": {"name": rec.get("provider") or "agent"},
                "request": {"uid": rec.get("call_id") or rec.get("hash")}},
        "actor": {"app_name": rec.get("app"), "user": {"name": rec.get("approved_by")} if rec.get("approved_by") else None},
        "metadata": {"product": {"name": NAME, "version": VERSION, "vendor_name": NAME},
                     "version": "1.3.0", "uid": rec.get("hash"), "sequence": rec.get("seq")},
        "unmapped": {k: rec.get(k) for k in ("model", "usage", "findings", "decision", "policy", "pii", "prev", "mac")
                     if rec.get(k) is not None},
    }


# ------------------------------------------------------------------ CEF

def _cef_escape(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", " ")


def to_cef(rec: Dict[str, Any]) -> str:
    event = rec.get("event", "")
    sev = SEVERITY_NUM.get(rec.get("severity", "none"), 0)
    if rec.get("status") == "blocked":
        sev = max(sev, 7)
    sig = {"llm.call": "100", "tool.call": "200", f"{NAME}.error": "900"}.get(event, "300")
    name = {"llm.call": "LLM call", "tool.call": "Agent tool call"}.get(event, event)
    ext = {
        "rt": str(_ts_ns(rec.get("ts", "")) // 1_000_000),
        "app": rec.get("app"),
        "act": rec.get("op") or rec.get("tool"),
        "outcome": rec.get("status"),
        "cs1Label": "model", "cs1": rec.get("model"),
        "cs2Label": "provider", "cs2": rec.get("provider") or rec.get("agent"),
        "cs3Label": "severity", "cs3": rec.get("severity"),
        "cs4Label": "decision", "cs4": rec.get("decision"),
        "cs5Label": "hash", "cs5": rec.get("hash"),
        "cs6Label": "policy", "cs6": rec.get("policy"),
        "cn1Label": "tokens", "cn1": (rec.get("usage") or {}).get("total"),
        "cn2Label": "seq", "cn2": rec.get("seq"),
        "suser": rec.get("approved_by"),
        "msg": json.dumps(rec.get("findings"), ensure_ascii=False)[:1000] if rec.get("findings") else None,
    }
    tail = " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items() if v is not None)
    return f"CEF:0|{NAME}|{NAME}|{VERSION}|{sig}|{name}|{sev}|{tail}"


def export_ledger(paths: Iterable[str], fmt: str) -> Iterator[str]:
    for rec in _iter_records(paths):
        if fmt == "otel":
            yield json.dumps(to_otel(rec), ensure_ascii=False)
        elif fmt == "ocsf":
            yield json.dumps(to_ocsf(rec), ensure_ascii=False)
        elif fmt == "cef":
            yield to_cef(rec)
        else:
            raise ValueError(f"unknown format: {fmt}")


# ------------------------------------------------------------------ SARIF

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def to_sarif(scan: Dict[str, Any], evaluations: List[Dict[str, Any]]) -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for f in scan.get("findings", []):
        rid = f["id"]
        rules.setdefault(rid, {"id": rid, "shortDescription": {"text": rid},
                               "defaultConfiguration": {"level": _SARIF_LEVEL.get(f["severity"], "warning")}})
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["msg"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"]}}}],
            "properties": {"severity": f["severity"]},
        })
    for ev in evaluations:
        for row in ev["controls"]:
            if row["status"] != "fail":
                continue
            rid = f"{ev['controls_id']}/{row['id']}"
            rules.setdefault(rid, {"id": rid, "shortDescription": {"text": row["title_en"]},
                                   "fullDescription": {"text": row["title_ru"]},
                                   "defaultConfiguration": {"level": "error"}})
            results.append({
                "ruleId": rid, "level": "error",
                "message": {"text": f"{row['title_en']}: " + "; ".join(row["notes"])},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "aiproof.json"}}}],
                "properties": {"control": row["id"], "set": ev["controls_id"], "phase": row["phase"]},
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": NAME, "version": VERSION, "informationUri": "https://github.com/scheltsin/aiproof",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }
