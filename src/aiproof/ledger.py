"""Tamper-evident append-only ledger (JSON Lines).

Each record carries ``seq``, ``prev`` (hash of the previous record) and ``hash``
(SHA-256 over the canonical JSON of the record without ``hash``/``mac``).
If a key is configured, ``mac`` = HMAC-SHA256(key, hash) is added, so a party
without the key cannot rewrite the chain even if they recompute all hashes.

Format id: ``aiproof/ledger/v0`` (see docs/spec/ledger-v0.md).

The ledger is deliberately boring: plain files, stdlib only, one lock per
process, safe to ship to a SIEM as-is.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from ._meta import LEDGER_FORMAT, NAME, VERSION

GENESIS = "0" * 64


def canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding used for hashing."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_hash(rec: Dict[str, Any]) -> str:
    body = {k: v for k, v in rec.items() if k not in ("hash", "mac")}
    return sha256_hex(canonical(body))


def record_mac(key: bytes, h: str) -> str:
    return hmac.new(key, h.encode("ascii"), hashlib.sha256).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    records: int
    last_hash: str
    errors: List[str]
    mac_checked: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "records": self.records,
            "last_hash": self.last_hash,
            "errors": self.errors,
            "mac_checked": self.mac_checked,
        }


class Ledger:
    """Append-only hash-chained JSONL ledger."""

    def __init__(self, path: str, key: Optional[bytes] = None, app: str = "app"):
        self.path = Path(path)
        self.key = key
        self.app = app
        self._lock = threading.Lock()
        self._seq = 0
        self._last = GENESIS
        self._loaded = False

    # ------------------------------------------------------------------ state
    def _load_tail(self) -> None:
        """Read the last record to continue the chain across restarts."""
        self._loaded = True
        if not self.path.exists():
            return
        last_line = b""
        with open(self.path, "rb") as f:
            # read from the end; ledgers can be large
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 4096
            buf = b""
            while size > 0:
                step = min(block, size)
                size -= step
                f.seek(size)
                buf = f.read(step) + buf
                if buf.count(b"\n") >= 2 or size == 0:
                    break
            lines = [ln for ln in buf.split(b"\n") if ln.strip()]
            if lines:
                last_line = lines[-1]
        if last_line:
            try:
                rec = json.loads(last_line.decode("utf-8"))
                self._seq = int(rec.get("seq", 0))
                self._last = rec.get("hash", GENESIS)
            except Exception:
                # corrupt tail: start a new chain segment but keep the file
                self._seq = 0
                self._last = GENESIS

    # ------------------------------------------------------------------ write
    def append(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            if not self._loaded:
                self._load_tail()
            self._seq += 1
            rec: Dict[str, Any] = {
                "fmt": LEDGER_FORMAT,
                "seq": self._seq,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int((time.time() % 1) * 1000):03d}Z",
                "app": self.app,
                "event": event,
                "prev": self._last,
                "lib": f"{NAME}/{VERSION}",
            }
            rec.update(payload)
            rec["hash"] = record_hash(rec)
            if self.key:
                rec["mac"] = record_mac(self.key, rec["hash"])
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
                f.flush()
            self._last = rec["hash"]
            return rec

    # ------------------------------------------------------------------ read
    def iter_records(self) -> Iterator[Dict[str, Any]]:
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def head(self) -> str:
        if not self._loaded:
            self._load_tail()
        return self._last


def verify_file(path: str, key: Optional[bytes] = None, expected_head: Optional[str] = None) -> VerifyResult:
    """Verify the hash chain (and MACs if a key is given) of a ledger file."""
    errors: List[str] = []
    prev = GENESIS
    seq = 0
    n = 0
    mac_checked = key is not None
    p = Path(path)
    if not p.exists():
        return VerifyResult(False, 0, GENESIS, [f"file not found: {path}"], mac_checked)
    with open(p, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception as e:
                errors.append(f"line {lineno}: invalid json ({e})")
                break
            n += 1
            if rec.get("seq") != seq + 1:
                errors.append(f"line {lineno}: seq {rec.get('seq')} expected {seq + 1}")
            if rec.get("prev") != prev:
                errors.append(f"line {lineno}: prev hash mismatch (chain broken)")
            h = record_hash(rec)
            if rec.get("hash") != h:
                errors.append(f"line {lineno}: record modified (hash mismatch)")
            if key is not None:
                if "mac" not in rec:
                    errors.append(f"line {lineno}: missing mac")
                elif not hmac.compare_digest(rec["mac"], record_mac(key, rec.get("hash", ""))):
                    errors.append(f"line {lineno}: mac mismatch (wrong key or forged record)")
            prev = rec.get("hash", h)
            seq = rec.get("seq", seq + 1) if isinstance(rec.get("seq"), int) else seq + 1
            if len(errors) > 50:
                errors.append("... too many errors")
                break
    if expected_head and prev != expected_head:
        errors.append(f"head mismatch: {prev} != {expected_head} (records removed from the tail?)")
    return VerifyResult(not errors, n, prev, errors, mac_checked)
