"""Integration surface: ``wrap(client)``, ``install()``, ``record()``.

* ``wrap(client)`` returns a transparent proxy around an OpenAI-compatible or
  Anthropic client. Only the ``create`` calls under ``chat.completions``,
  ``completions``, ``responses``, ``embeddings`` and ``messages`` are
  intercepted; everything else passes through untouched.
* ``install()`` monkey-patches the SDK classes so every client in the process
  is covered without touching call sites (Sentry-style).
* ``record()`` is a context manager for anything else (custom HTTP, local
  models, RAG pipelines, tool calls).
"""
from __future__ import annotations

import contextlib
import functools
import inspect
from typing import Any, Callable, Dict, Iterable, Optional

from .core import Blocked, Call, Guard

_INTERCEPT_OPS = {
    "chat.completions": "chat.completions",
    "completions": "completions",
    "responses": "responses",
    "embeddings": "embeddings",
    "messages": "messages",
    "beta.messages": "messages",
    "beta.chat.completions": "chat.completions",
}
_PROXY_ATTRS = {"chat", "completions", "responses", "embeddings", "messages", "beta"}
_INTERCEPT_METHODS = {"create", "parse", "stream"}

_default_guard: Optional[Guard] = None


def guard(policy: Any = None) -> Guard:
    """Return the process-wide Guard (created on first use)."""
    global _default_guard
    if _default_guard is None or policy is not None:
        _default_guard = Guard(policy)
    return _default_guard


def _provider_of(obj: Any) -> str:
    mod = type(obj).__module__ or ""
    if mod.startswith("anthropic"):
        return "anthropic"
    if mod.startswith("openai"):
        base = getattr(obj, "base_url", None) or getattr(getattr(obj, "_client", None), "base_url", None)
        b = str(base or "")
        for key, name in (("gigachat", "gigachat"), ("yandex", "yandexgpt"), ("11434", "ollama"),
                          ("localhost", "local"), ("127.0.0.1", "local"), ("deepseek", "deepseek"),
                          ("openrouter", "openrouter"), ("mistral", "mistral")):
            if key in b:
                return f"openai-compatible/{name}"
        return "openai"
    return mod.split(".")[0] or "unknown"


# ------------------------------------------------------------------ streaming

def _delta_text(chunk: Any) -> str:
    try:
        # openai chat chunk
        ch = getattr(chunk, "choices", None)
        if ch:
            d = getattr(ch[0], "delta", None)
            t = getattr(d, "content", None)
            if isinstance(t, str):
                return t
        # openai responses stream event
        if getattr(chunk, "type", "") == "response.output_text.delta":
            return getattr(chunk, "delta", "") or ""
        # anthropic
        if getattr(chunk, "type", "") == "content_block_delta":
            d = getattr(chunk, "delta", None)
            t = getattr(d, "text", None)
            if isinstance(t, str):
                return t
        if isinstance(chunk, dict):
            ch = chunk.get("choices")
            if ch and isinstance(ch, list):
                return ((ch[0].get("delta") or {}).get("content")) or ""
    except Exception:
        pass
    return ""


def _usage_of_chunk(chunk: Any) -> Dict[str, int]:
    from .core import extract_usage
    u = extract_usage(chunk)
    if u:
        return u
    # anthropic message_delta carries output_tokens
    try:
        if getattr(chunk, "type", "") == "message_delta":
            ot = getattr(getattr(chunk, "usage", None), "output_tokens", None)
            if isinstance(ot, int):
                return {"output": ot, "total": ot}
    except Exception:
        pass
    return {}


class _StreamProxy:
    """Wraps a sync stream; records once it is exhausted or closed."""

    def __init__(self, stream: Any, g: Guard, call: Call):
        self._s = stream
        self._g = g
        self._call = call
        self._buf: list = []
        self._usage: Dict[str, int] = {}
        self._done = False

    def __iter__(self):
        try:
            for chunk in self._s:
                self._buf.append(_delta_text(chunk))
                u = _usage_of_chunk(chunk)
                if u:
                    self._usage.update(u)
                yield chunk
        except BaseException as e:
            self._finish(error=e)
            raise
        self._finish()

    def _finish(self, error: Optional[BaseException] = None) -> None:
        if self._done:
            return
        self._done = True
        self._g.after(self._call, None, usage=self._usage, error=error, output_text="".join(self._buf))

    def close(self):
        self._finish()
        c = getattr(self._s, "close", None)
        if callable(c):
            c()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def __getattr__(self, name):
        return getattr(self._s, name)


class _AsyncStreamProxy(_StreamProxy):
    async def __aiter__(self):
        try:
            async for chunk in self._s:
                self._buf.append(_delta_text(chunk))
                u = _usage_of_chunk(chunk)
                if u:
                    self._usage.update(u)
                yield chunk
        except BaseException as e:
            self._finish(error=e)
            raise
        self._finish()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        self.close()


# ------------------------------------------------------------------ wrapping

def _wrap_method(fn: Callable, g: Guard, provider: str, op: str) -> Callable:
    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def awrapper(*args, **kwargs):
            call = g.before(provider, op, str(kwargs.get("model", "")), kwargs)
            try:
                result = await fn(*args, **kwargs)
            except BaseException as e:
                g.after(call, error=e)
                raise
            if kwargs.get("stream") or op == "stream":
                return _AsyncStreamProxy(result, g, call)
            g.after(call, result)
            return result
        return awrapper

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        call = g.before(provider, op, str(kwargs.get("model", "")), kwargs)
        try:
            result = fn(*args, **kwargs)
        except BaseException as e:
            g.after(call, error=e)
            raise
        if inspect.isawaitable(result):
            async def _await():
                try:
                    r = await result
                except BaseException as e:
                    g.after(call, error=e)
                    raise
                if kwargs.get("stream"):
                    return _AsyncStreamProxy(r, g, call)
                g.after(call, r)
                return r
            return _await()
        if kwargs.get("stream") or op == "stream":
            if hasattr(result, "__aiter__"):
                return _AsyncStreamProxy(result, g, call)
            return _StreamProxy(result, g, call)
        g.after(call, result)
        return result
    return wrapper


class _Proxy:
    """Attribute proxy that intercepts ``create`` under known resource paths."""

    def __init__(self, target: Any, g: Guard, provider: str, path: str = ""):
        object.__setattr__(self, "_t", target)
        object.__setattr__(self, "_g", g)
        object.__setattr__(self, "_prov", provider)
        object.__setattr__(self, "_path", path)

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._t, name)
        path = f"{self._path}.{name}".strip(".") if self._path else name
        if name in _INTERCEPT_METHODS and self._path in _INTERCEPT_OPS and callable(attr):
            op = _INTERCEPT_OPS[self._path] + ("" if name == "create" else f".{name}")
            return _wrap_method(attr, self._g, self._prov, op)
        if name in _PROXY_ATTRS and not callable(attr):
            return _Proxy(attr, self._g, self._prov, path)
        if name in _PROXY_ATTRS and callable(attr) and not inspect.isroutine(attr):
            return _Proxy(attr, self._g, self._prov, path)
        return attr

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._t, name, value)

    def __repr__(self) -> str:
        return f"<aiproof.wrap {self._t!r}>"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        c = getattr(self._t, "close", None)
        if callable(c):
            c()


def wrap(client: Any, policy: Any = None, provider: Optional[str] = None) -> Any:
    """Return a proxy around ``client`` that records every model call.

    >>> client = aiproof.wrap(OpenAI(base_url=...), policy="ru-fstek-117")
    """
    g = guard(policy) if policy is not None else guard()
    return _Proxy(client, g, provider or _provider_of(client))


# ------------------------------------------------------------------ install

_installed: Dict[str, Callable] = {}


def install(policy: Any = None) -> Dict[str, bool]:
    """Patch the OpenAI / Anthropic SDKs in-process. Returns what was patched."""
    g = guard(policy) if policy is not None else guard()
    patched: Dict[str, bool] = {}

    targets = [
        ("openai.resources.chat.completions", "Completions", "create", "openai", "chat.completions"),
        ("openai.resources.chat.completions", "AsyncCompletions", "create", "openai", "chat.completions"),
        ("openai.resources.completions", "Completions", "create", "openai", "completions"),
        ("openai.resources.completions", "AsyncCompletions", "create", "openai", "completions"),
        ("openai.resources.responses", "Responses", "create", "openai", "responses"),
        ("openai.resources.responses", "AsyncResponses", "create", "openai", "responses"),
        ("openai.resources.embeddings", "Embeddings", "create", "openai", "embeddings"),
        ("anthropic.resources.messages", "Messages", "create", "anthropic", "messages"),
        ("anthropic.resources.messages", "AsyncMessages", "create", "anthropic", "messages"),
    ]
    import importlib
    for mod_name, cls_name, meth, provider, op in targets:
        key = f"{mod_name}.{cls_name}.{meth}"
        try:
            mod = importlib.import_module(mod_name)
            cls = getattr(mod, cls_name)
            if key in _installed:
                patched[key] = True
                continue
            original = getattr(cls, meth)

            def make(original=original, provider=provider, op=op):
                if inspect.iscoroutinefunction(original):
                    async def patched_async(self, *args, **kwargs):
                        prov = provider
                        try:
                            prov = _provider_of(self._client)  # type: ignore[attr-defined]
                        except Exception:
                            pass
                        return await _wrap_method(functools.partial(original, self), g, prov, op)(*args, **kwargs)
                    return patched_async

                def patched_sync(self, *args, **kwargs):
                    prov = provider
                    try:
                        prov = _provider_of(self._client)  # type: ignore[attr-defined]
                    except Exception:
                        pass
                    return _wrap_method(functools.partial(original, self), g, prov, op)(*args, **kwargs)
                return patched_sync

            setattr(cls, meth, make())
            _installed[key] = original
            patched[key] = True
        except Exception:
            patched[key] = False
    return patched


def uninstall() -> None:
    import importlib
    for key, original in list(_installed.items()):
        mod_name, cls_name, meth = key.rsplit(".", 2)
        try:
            cls = getattr(importlib.import_module(mod_name), cls_name)
            setattr(cls, meth, original)
        except Exception:
            pass
        _installed.pop(key, None)


# ------------------------------------------------------------------ record()

class Recorded:
    """Handle returned by ``record()``; set ``.output`` / ``.usage`` before exit."""

    def __init__(self, call: Call):
        self.call = call
        self.output: Any = None
        self.usage: Optional[Dict[str, int]] = None


@contextlib.contextmanager
def record(op: str, model: str = "", input: Any = None, provider: str = "custom",
           policy: Any = None, **meta: Any) -> Iterable[Recorded]:
    """Record any custom model / tool call.

    >>> with aiproof.record("rag.answer", model="gigachat", input=question) as r:
    ...     r.output = answer
    """
    g = guard(policy) if policy is not None else guard()
    call = g.before(provider, op, model, input, **meta)
    rec = Recorded(call)
    try:
        yield rec
    except Blocked:
        raise
    except BaseException as e:
        g.after(call, error=e)
        raise
    out = rec.output
    g.after(call, out, usage=rec.usage, output_text=out if isinstance(out, str) else None)
