"""Zero-code integration: a local reverse proxy for OpenAI-compatible APIs.

    aiproof proxy --upstream https://api.openai.com --listen 127.0.0.1:8787
    export OPENAI_BASE_URL=http://127.0.0.1:8787/v1

Every request/response passing through is recorded in the ledger with the
same policy as the SDK wrapper. Stdlib only; fine for dev, CI and small
services. For high load put it behind your gateway or use ``install()``.
"""
from __future__ import annotations

import http.client
import json
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Tuple
from urllib.parse import urlsplit

from .core import Blocked, Guard, extract_text, extract_usage

_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
        "transfer-encoding", "upgrade", "host", "content-length", "accept-encoding"}


def _op_of(path: str) -> str:
    p = path.split("?")[0]
    if "/chat/completions" in p:
        return "chat.completions"
    if "/responses" in p:
        return "responses"
    if "/embeddings" in p:
        return "embeddings"
    if "/messages" in p:
        return "messages"
    if "/completions" in p:
        return "completions"
    return "http:" + p


def _provider_of(upstream: str) -> str:
    u = upstream.lower()
    for key, name in (("gigachat", "gigachat"), ("yandex", "yandexgpt"), ("anthropic", "anthropic"),
                      ("openai.com", "openai"), ("11434", "ollama")):
        if key in u:
            return name
    return "openai-compatible"


def _parse_sse_text(body: bytes) -> Tuple[str, Dict[str, int]]:
    """Reassemble assistant text and usage from an SSE stream body."""
    text: List[str] = []
    usage: Dict[str, int] = {}
    for raw in body.split(b"\n"):
        line = raw.strip()
        if not line.startswith(b"data:"):
            continue
        data = line[5:].strip()
        if data == b"[DONE]" or not data:
            continue
        try:
            obj = json.loads(data)
        except Exception:
            continue
        ch = obj.get("choices")
        if isinstance(ch, list) and ch:
            d = (ch[0].get("delta") or {}).get("content")
            if isinstance(d, str):
                text.append(d)
        if obj.get("type") == "response.output_text.delta":
            text.append(obj.get("delta") or "")
        if obj.get("type") == "content_block_delta":
            t = (obj.get("delta") or {}).get("text")
            if isinstance(t, str):
                text.append(t)
        u = extract_usage(obj)
        if u:
            usage.update(u)
    return "".join(text), usage


def make_handler(upstream: str, g: Guard):
    parts = urlsplit(upstream)
    scheme, netloc = parts.scheme or "https", parts.netloc
    base_path = parts.path.rstrip("/")
    provider = _provider_of(upstream)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # quieter
            sys.stderr.write("[aiproof proxy] " + (fmt % args) + "\n")

        def _forward(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            op = _op_of(self.path)
            req_obj: Any = None
            if body:
                try:
                    req_obj = json.loads(body.decode("utf-8"))
                except Exception:
                    req_obj = {"raw": body[:2000].decode("utf-8", "replace")}
            model = str((req_obj or {}).get("model", "")) if isinstance(req_obj, dict) else ""
            is_llm = not op.startswith("http:")
            call = None
            if is_llm:
                try:
                    call = g.before(provider, op, model, req_obj)
                except Blocked as e:
                    self._reply(403, {"error": {"message": f"blocked by aiproof policy: {e.reason}",
                                                "type": "aiproof_blocked"}})
                    return
                except Exception as e:
                    self._reply(429, {"error": {"message": str(e), "type": "aiproof_quota"}})
                    return

            conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
            kwargs: Dict[str, Any] = {"timeout": 600}
            if scheme == "https":
                kwargs["context"] = ssl.create_default_context()
            conn = conn_cls(netloc, **kwargs)
            headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP}
            headers["Host"] = netloc
            if body:
                headers["Content-Length"] = str(len(body))
            try:
                conn.request(self.command, base_path + self.path, body=body or None, headers=headers)
                resp = conn.getresponse()
            except Exception as e:
                if call:
                    g.after(call, error=e)
                self._reply(502, {"error": {"message": f"upstream error: {e}"}})
                return

            self.send_response(resp.status)
            streaming = "text/event-stream" in (resp.getheader("Content-Type") or "")
            for k, v in resp.getheaders():
                if k.lower() in _HOP or k.lower() == "content-length":
                    continue
                self.send_header(k, v)
            collected = bytearray()
            if streaming:
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                while True:
                    chunk = resp.read1(65536) if hasattr(resp, "read1") else resp.read(65536)
                    if not chunk:
                        break
                    collected += chunk
                    self.wfile.write(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
            else:
                data = resp.read()
                collected += data
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            conn.close()

            if call:
                try:
                    if resp.status >= 400:
                        g.after(call, error=RuntimeError(f"HTTP {resp.status}: {bytes(collected[:300])!r}"))
                    elif streaming:
                        text, usage = _parse_sse_text(bytes(collected))
                        g.after(call, None, usage=usage, output_text=text)
                    else:
                        obj = json.loads(bytes(collected).decode("utf-8"))
                        g.after(call, obj, usage=extract_usage(obj), output_text=extract_text(obj))
                except Blocked:
                    pass  # response already sent; the finding is in the ledger
                except Exception as e:
                    g.after(call, error=e)

        def _reply(self, status: int, obj: Dict[str, Any]) -> None:
            data = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _forward

    return Handler


def serve(upstream: str, listen: str = "127.0.0.1:8787", policy: Any = None) -> None:
    host, _, port = listen.rpartition(":")
    g = Guard(policy)
    server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), make_handler(upstream, g))
    print(f"aiproof proxy: http://{host or '127.0.0.1'}:{port} -> {upstream} (policy={g.policy.name}, "
          f"ledger={g.policy.ledger_path})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
