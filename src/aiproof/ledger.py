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

try:
    import fcntl  # POSIX advisory locks: several processes may append to one ledger
except ImportError:  # pragma: no cover  (Windows)
    fcntl = None
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
    chained_from: Optional[str] = None
    last_seq: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "records": self.records,
            "last_hash": self.last_hash,
            "errors": self.errors,
            "mac_checked": self.mac_checked,
        }


class _NoClose:
    """Context manager that yields an open file without closing it on exit."""

    def __init__(self, f):
        self.f = f

    def __enter__(self):
        return self.f

    def __exit__(self, *a):
        return False


class Ledger:
    """Append-only hash-chained JSONL ledger. Safe for several threads and several
    processes (gunicorn/uvicorn workers) writing to the same file: appends are
    serialised with an advisory file lock and the chain is re-synced from the
    file tail whenever another writer has added records. Files are rotated at
    ``rotate_mb`` and the chain continues into the next file."""

    def __init__(self, path: str, key: Optional[bytes] = None, app: str = "app", rotate_mb: int = 256):
        self.path = Path(path)
        self.key = key
        self.app = app
        self.rotate_bytes = int(rotate_mb) * 1024 * 1024 if rotate_mb else 0
        self._lock = threading.Lock()
        self._seq = 0
        self._last = GENESIS
        self._loaded = False
        self._known_size = -1  # size after our last write; if the file grew, another process wrote

    # ------------------------------------------------------------------ state
    def _load_tail(self, fobj=None) -> None:
        """Read the last record to continue the chain across restarts / other writers."""
        self._loaded = True
        if fobj is None and not self.path.exists():
            self._known_size = 0
            return
        last_line = b""
        with (open(self.path, "rb") if fobj is None else _NoClose(fobj)) as f:
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
            f.seek(0, os.SEEK_END)
            self._known_size = f.tell()
        if last_line:
            try:
                rec = json.loads(last_line.decode("utf-8"))
                self._seq = int(rec.get("seq", 0))
                self._last = rec.get("hash", GENESIS)
            except Exception:
                # corrupt tail: start a new chain segment but keep the file
                self._seq = 0
                self._last = GENESIS

    def _rotate_locked(self, f) -> None:
        """Rename the full file; the chain continues into a fresh file (first prev = last hash)."""
        ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        target = self.path.with_name(f"{self.path.stem}-{ts}-{self._seq:09d}{self.path.suffix}")
        try:
            os.replace(self.path, target)
        except OSError:
            pass
        self._known_size = 0

    # ------------------------------------------------------------------ write
    def append(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            f = open(self.path, "a+b")
            try:
                if fcntl is not None:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                # the file may have been rotated by another process after we opened it
                try:
                    if os.fstat(f.fileno()).st_ino != os.stat(self.path).st_ino:
                        f.close()
                        f = open(self.path, "a+b")
                        if fcntl is not None:
                            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                except FileNotFoundError:
                    pass
                size = os.fstat(f.fileno()).st_size
                if not self._loaded or size != self._known_size:
                    self._load_tail(f)  # first write, restart, or another process appended: re-sync the chain
                if self.rotate_bytes and size >= self.rotate_bytes:
                    f.close()
                    self._rotate_locked(f)
                    f = open(self.path, "a+b")
                    if fcntl is not None:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                rec = self._make_record(event, payload)
                line = (json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
                f.write(line)
                f.flush()
                self._known_size = os.fstat(f.fileno()).st_size
                self._last = rec["hash"]
                return rec
            finally:
                try:
                    if fcntl is not None:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                finally:
                    f.close()

    def _make_record(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
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


def verify_file(path: str, key: Optional[bytes] = None, expected_head: Optional[str] = None,
                prev: Optional[str] = None, seq: Optional[int] = None) -> VerifyResult:
    """Verify the hash chain (and MACs if a key is given) of a ledger file.

    A rotated file may start mid-chain: its first record then carries the hash of
    the last record of the previous file. Pass ``prev``/``seq`` from the previous
    file to check continuity; without them a mid-chain start is accepted and
    reported via ``chained_from``.
    """
    errors: List[str] = []
    chained_from: Optional[str] = None
    first = True
    prev = prev if prev is not None else GENESIS
    seq = seq if seq is not None else 0
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
            if first and prev == GENESIS and rec.get("prev") not in (GENESIS, None) and isinstance(rec.get("seq"), int):
                # rotated segment: accept its own starting point
                chained_from = rec.get("prev")
                prev = chained_from
                seq = rec["seq"] - 1
            first = False
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
    res = VerifyResult(not errors, n, prev, errors, mac_checked)
    res.chained_from = chained_from
    res.last_seq = seq
    return res


def ledger_files(directory: str) -> List[str]:
    """All ledger segments in a directory, oldest first (rotated files carry the seq in the name)."""
    d = Path(directory)
    files = [p for p in d.glob("*.jsonl")]

    def key(p: Path):
        try:
            with open(p, "r", encoding="utf-8") as f:
                first = json.loads(f.readline())
            return (int(first.get("seq", 0)), p.name)
        except Exception:
            return (1 << 62, p.name)
    return [str(p) for p in sorted(files, key=key)]


def verify_chain(directory: str, key: Optional[bytes] = None) -> VerifyResult:
    """Verify every segment in a directory as one continuous chain."""
    prev, seq, n, errors = GENESIS, 0, 0, []
    mac_checked = key is not None
    for path in ledger_files(directory):
        r = verify_file(path, key, prev=prev, seq=seq)
        n += r.records
        errors.extend(f"{Path(path).name}: {e}" for e in r.errors)
        prev, seq = r.last_hash, r.last_seq
    return VerifyResult(not errors, n, prev, errors, mac_checked)
