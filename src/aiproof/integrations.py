"""Integrations beyond the OpenAI / Anthropic SDKs, for closed contours where
those SDKs are not allowed or not used:

* official ``gigachat`` SDK (``client.chat(...)``, ``client.chat.create``, ``stream``, async);
* raw HTTP through ``requests`` / ``httpx`` to any LLM endpoint (YandexGPT
  Foundation Models API, GigaChat REST, Ollama, vLLM, LM Studio, custom
  gateways) – enabled with ``aiproof.install(http=True)``;
* a re-entrancy guard so SDK wrappers and the HTTP hook never record the
  same call twice.
"""
from __future__ import annotations

import contextvars
import functools
import inspect
import json
import re
from typing import Any, Callable, Dict, Optional

from .core import Guard, extract_text, extract_usage

_in_sdk_call: contextvars.ContextVar[bool] = contextvars.ContextVar("aiproof_in_sdk_call", default=False)

LLM_PATH = re.compile(
    r"/(?:v\d+/)?(?:chat/completions|completions|responses|messages|embeddings"
    r"|foundationModels/v\d+/(?:completion|completionAsync|textGeneration|tokenize)"
    r"|api/(?:chat|generate|embed|embeddings)"
    r"|api/v\d+/chat/completions)(?:\?|$)"
)


def _model_of(payload: Any, fallback: str = "") -> str:
    if isinstance(payload, dict):
        m = payload.get("model") or payload.get("modelUri")
        return str(m) if m else fallback
    m = getattr(payload, "model", None) or getattr(payload, "modelUri", None)
    return str(m) if m else fallback


def _client_model(client: Any) -> str:
    for path in (("_settings", "model"), ("model",), ("settings", "model")):
        obj = client
        try:
            for p in path:
                obj = getattr(obj, p)
            if isinstance(obj, str) and obj:
                return obj
        except Exception:
            continue
    return ""


def _yandex_text(obj: Any) -> str:
    """YandexGPT Foundation Models API: result.alternatives[0].message.text"""
    try:
        res = obj.get("result", obj) if isinstance(obj, dict) else {}
        alts = res.get("alternatives") or []
        return "\n".join(a.get("message", {}).get("text", "") for a in alts if isinstance(a, dict))
    except Exception:
        return ""


def _yandex_usage(obj: Any) -> Dict[str, int]:
    try:
        u = (obj.get("result", obj) if isinstance(obj, dict) else {}).get("usage") or {}
        out = {}
        for src, dst in (("inputTextTokens", "input"), ("completionTokens", "output"), ("totalTokens", "total")):
            if src in u:
                out[dst] = int(u[src])
        return out
    except Exception:
        return {}


def response_text(obj: Any) -> str:
    return extract_text(obj) or _yandex_text(obj) or (obj.get("response", "") if isinstance(obj, dict) else "")


def response_usage(obj: Any) -> Dict[str, int]:
    u = extract_usage(obj) or _yandex_usage(obj)
    if not u and isinstance(obj, dict) and "eval_count" in obj:  # ollama native
        u = {"input": int(obj.get("prompt_eval_count", 0)), "output": int(obj.get("eval_count", 0))}
        u["total"] = u["input"] + u["output"]
    return u


# ------------------------------------------------------------------ positional wrapper (gigachat & co)

def wrap_positional(fn: Callable, g: Guard, provider: str, op: str, model_getter: Callable[[], str],
                    stream: bool = False) -> Callable:
    """Wrap ``fn(payload, *rest, **kw)`` where the request is the first positional argument."""
    from .client import _StreamProxy, _AsyncStreamProxy

    def _payload(args, kwargs):
        return args[0] if args else kwargs.get("payload", kwargs)

    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def awrapper(*args, **kwargs):
            if _in_sdk_call.get():  # nested SDK call (e.g. chat() -> _chat()): record once, at the outer level
                return await fn(*args, **kwargs)
            payload = _payload(args, kwargs)
            call = g.before(provider, op, _model_of(payload, model_getter()), payload)
            tok = _in_sdk_call.set(True)
            try:
                result = await fn(*args, **kwargs)
            except BaseException as e:
                g.after(call, error=e)
                raise
            finally:
                _in_sdk_call.reset(tok)
            if stream:
                return _AsyncStreamProxy(result, g, call)
            g.after(call, result)
            return result
        return awrapper

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if _in_sdk_call.get():
            return fn(*args, **kwargs)
        payload = _payload(args, kwargs)
        call = g.before(provider, op, _model_of(payload, model_getter()), payload)
        tok = _in_sdk_call.set(True)
        try:
            result = fn(*args, **kwargs)
        except BaseException as e:
            g.after(call, error=e)
            raise
        finally:
            _in_sdk_call.reset(tok)
        if stream:
            return _AsyncStreamProxy(result, g, call) if hasattr(result, "__aiter__") else _StreamProxy(result, g, call)
        g.after(call, result)
        return result
    return wrapper


_GIGACHAT_METHODS = [
    # (attribute, op, stream?)  – newer SDK (namespaces) and older SDK (direct methods)
    ("_chat", "chat", False), ("_chat_create", "chat.completions", False), ("_chat_stream", "chat.stream", True),
    ("_achat", "chat", False), ("_achat_create", "chat.completions", False), ("_achat_stream", "chat.stream", True),
    ("chat", "chat", False), ("achat", "chat", False), ("stream", "chat.stream", True), ("astream", "chat.stream", True),
]


def patch_gigachat_instance(client: Any, g: Guard) -> Any:
    """Patch one GigaChat client instance in place (used by ``wrap()``)."""
    for attr, op, is_stream in _GIGACHAT_METHODS:
        fn = getattr(type(client), attr, None)
        if fn is None or not callable(fn):
            continue
        bound = getattr(client, attr)
        if not inspect.isroutine(bound):
            continue  # cached_property namespace in newer SDKs; its calls go through _chat* which we patch
        setattr(client, attr, wrap_positional(bound, g, "gigachat", op, lambda c=client: _client_model(c), is_stream))
    return client


def install_gigachat(g: Guard) -> Dict[str, bool]:
    """Patch the gigachat SDK classes process-wide."""
    patched: Dict[str, bool] = {}
    try:
        import gigachat.client as gc
    except Exception:
        return patched
    for cls_name in ("GigaChatSyncClient", "GigaChatAsyncClient", "GigaChat"):
        cls = getattr(gc, cls_name, None)
        if cls is None:
            continue
        for attr, op, is_stream in _GIGACHAT_METHODS:
            if attr not in cls.__dict__:
                continue
            original = cls.__dict__[attr]
            if not inspect.isroutine(original):
                continue
            key = f"gigachat.client.{cls_name}.{attr}"
            if key in _patched_originals:
                patched[key] = True
                continue

            def make(original=original, op=op, is_stream=is_stream):
                if inspect.iscoroutinefunction(original):
                    async def patched_async(self, *args, **kwargs):
                        return await wrap_positional(functools.partial(original, self), g, "gigachat", op,
                                                     lambda: _client_model(self), is_stream)(*args, **kwargs)
                    return patched_async

                def patched_sync(self, *args, **kwargs):
                    return wrap_positional(functools.partial(original, self), g, "gigachat", op,
                                           lambda: _client_model(self), is_stream)(*args, **kwargs)
                return patched_sync

            setattr(cls, attr, make())
            _patched_originals[key] = (cls, attr, original)
            patched[key] = True
    return patched


_patched_originals: Dict[str, Any] = {}


# ------------------------------------------------------------------ raw HTTP (requests / httpx)

def _provider_from_url(url: str) -> str:
    u = url.lower()
    for key, name in (("gigachat", "gigachat"), ("yandex", "yandexgpt"), ("openai.com", "openai"),
                      ("anthropic.com", "anthropic"), ("11434", "ollama"), ("localhost", "local"), ("127.0.0.1", "local")):
        if key in u:
            return f"http/{name}"
    return "http"


def _op_from_url(url: str) -> str:
    m = LLM_PATH.search(url.split("?")[0] + "?")
    return "http:" + (m.group(0).strip("?/") if m else url.split("?")[0][-60:])


def _json_body(data: Any) -> Any:
    if data is None:
        return None
    if isinstance(data, (bytes, bytearray)):
        try:
            return json.loads(bytes(data).decode("utf-8"))
        except Exception:
            return {"raw": bytes(data)[:2000].decode("utf-8", "replace")}
    if isinstance(data, str):
        try:
            return json.loads(data)
        except Exception:
            return {"raw": data[:2000]}
    return data


def install_http(g: Guard) -> Dict[str, bool]:
    """Record LLM calls made with ``requests`` and ``httpx`` (sync and async)."""
    patched: Dict[str, bool] = {}

    # requests
    try:
        import requests
        key = "requests.Session.request"
        if key not in _patched_originals:
            original = requests.Session.request

            def request(self, method, url, *args, original=original, **kwargs):
                if _in_sdk_call.get() or not LLM_PATH.search(str(url).split("?")[0] + "?"):
                    return original(self, method, url, *args, **kwargs)
                body = kwargs.get("json") if kwargs.get("json") is not None else _json_body(kwargs.get("data"))
                call = g.before(_provider_from_url(str(url)), _op_from_url(str(url)), _model_of(body), body)
                try:
                    resp = original(self, method, url, *args, **kwargs)
                except BaseException as e:
                    g.after(call, error=e)
                    raise
                try:
                    if resp.status_code >= 400:
                        g.after(call, error=RuntimeError(f"HTTP {resp.status_code}: {resp.text[:300]}"))
                    elif kwargs.get("stream") or "text/event-stream" in resp.headers.get("content-type", ""):
                        g.after(call, None, output_text="<stream>")
                    else:
                        obj = resp.json()
                        g.after(call, obj, usage=response_usage(obj), output_text=response_text(obj))
                except Exception as e:
                    g.after(call, error=e)
                return resp

            requests.Session.request = request
            _patched_originals[key] = (requests.Session, "request", original)
        patched[key] = True
    except ImportError:
        patched["requests.Session.request"] = False

    # httpx
    try:
        import httpx
        for cls_name in ("Client", "AsyncClient"):
            cls = getattr(httpx, cls_name)
            key = f"httpx.{cls_name}.send"
            if key in _patched_originals:
                patched[key] = True
                continue
            original = cls.send

            def make(original=original, is_async=(cls_name == "AsyncClient")):
                def _begin(request):
                    url = str(request.url)
                    if _in_sdk_call.get() or not LLM_PATH.search(url.split("?")[0] + "?"):
                        return None
                    body = _json_body(request.content) if request.content else None
                    return g.before(_provider_from_url(url), _op_from_url(url), _model_of(body), body)

                def _end(call, resp):
                    try:
                        if resp.status_code >= 400:
                            g.after(call, error=RuntimeError(f"HTTP {resp.status_code}"))
                        elif "text/event-stream" in resp.headers.get("content-type", "") or not hasattr(resp, "_content"):
                            g.after(call, None, output_text="<stream>")
                        else:
                            obj = resp.json()
                            g.after(call, obj, usage=response_usage(obj), output_text=response_text(obj))
                    except Exception as e:
                        g.after(call, error=e)

                if is_async:
                    async def send(self, request, *args, **kwargs):
                        call = _begin(request)
                        try:
                            resp = await original(self, request, *args, **kwargs)
                        except BaseException as e:
                            if call:
                                g.after(call, error=e)
                            raise
                        if call:
                            if not kwargs.get("stream"):
                                await resp.aread()
                            _end(call, resp)
                        return resp
                    return send

                def send(self, request, *args, **kwargs):
                    call = _begin(request)
                    try:
                        resp = original(self, request, *args, **kwargs)
                    except BaseException as e:
                        if call:
                            g.after(call, error=e)
                        raise
                    if call:
                        if not kwargs.get("stream"):
                            resp.read()
                        _end(call, resp)
                    return resp
                return send

            cls.send = make()
            _patched_originals[key] = (cls, "send", original)
            patched[key] = True
    except ImportError:
        patched["httpx.Client.send"] = False
    return patched


def uninstall_all() -> None:
    for key, (cls, attr, original) in list(_patched_originals.items()):
        try:
            setattr(cls, attr, original)
        except Exception:
            pass
        _patched_originals.pop(key, None)


def mark_sdk_call() -> Optional[contextvars.Token]:
    """Used by the OpenAI/Anthropic wrappers so the HTTP hook skips their transport."""
    return _in_sdk_call.set(True)


def unmark_sdk_call(tok: Optional[contextvars.Token]) -> None:
    if tok is not None:
        _in_sdk_call.reset(tok)
