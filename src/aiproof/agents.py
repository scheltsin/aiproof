"""Agent-side integrations: LangChain callback handler and MCP (FastMCP) tool hook.

Both route through ``Guard.tool_call`` so the tool allowlist / approval policy
applies, and through the LLM record path for model calls made by chains.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from .core import Blocked, Guard

# ------------------------------------------------------------------ LangChain

def langchain_handler(policy: Any = None, agent: Optional[str] = None):
    """Return a ``BaseCallbackHandler`` that records LLM calls and tool calls of
    LangChain / LangGraph chains in the ledger.

    >>> chain.invoke(x, config={"callbacks": [aiproof.langchain_handler(agent="support")]})
    """
    from langchain_core.callbacks import BaseCallbackHandler

    from .client import guard

    g: Guard = guard(policy) if policy is not None else guard()

    class AiproofCallbackHandler(BaseCallbackHandler):
        raise_error = True  # a policy Blocked must stop the chain

        def __init__(self) -> None:
            self._calls: Dict[Any, Any] = {}
            self._tools: Dict[Any, Any] = {}

        # ---- model calls
        def on_llm_start(self, serialized, prompts, *, run_id, **kw):
            model = _lc_model(serialized, kw)
            self._calls[run_id] = g.before("langchain", "llm", model, {"prompts": prompts}, agent=agent or "")

        def on_chat_model_start(self, serialized, messages, *, run_id, **kw):
            model = _lc_model(serialized, kw)
            plain = [[_lc_msg(m) for m in batch] for batch in messages]
            self._calls[run_id] = g.before("langchain", "chat", model, {"messages": plain}, agent=agent or "")

        def on_llm_end(self, response, *, run_id, **kw):
            call = self._calls.pop(run_id, None)
            if call is None:
                return
            text, usage = _lc_response(response)
            g.after(call, None, usage=usage, output_text=text)

        def on_llm_error(self, error, *, run_id, **kw):
            call = self._calls.pop(run_id, None)
            if call is not None:
                g.after(call, error=error)

        # ---- tools
        def on_tool_start(self, serialized, input_str, *, run_id, inputs=None, **kw):
            name = (serialized or {}).get("name") or kw.get("name") or "tool"
            self._tools[run_id] = (name, inputs if inputs is not None else input_str, time.time())
            g.tool_call(name, inputs if inputs is not None else input_str, agent=agent, gate_only=True)

        def on_tool_end(self, output, *, run_id, **kw):
            name, args, t0 = self._tools.pop(run_id, ("tool", None, time.time()))
            g.tool_call(name, args, result=_lc_tool_output(output), agent=agent, enforce=False,
                        latency_ms=int((time.time() - t0) * 1000))

        def on_tool_error(self, error, *, run_id, **kw):
            name, args, t0 = self._tools.pop(run_id, ("tool", None, time.time()))
            if isinstance(error, Blocked):
                return  # already recorded by the gate
            g.tool_call(name, args, error=error, agent=agent, enforce=False,
                        latency_ms=int((time.time() - t0) * 1000))

    return AiproofCallbackHandler()


def _lc_model(serialized: Any, kw: Dict[str, Any]) -> str:
    inv = kw.get("invocation_params") or {}
    for key in ("model", "model_name", "model_id"):
        if inv.get(key):
            return str(inv[key])
    s = serialized or {}
    kwargs = s.get("kwargs") or {}
    for key in ("model", "model_name"):
        if kwargs.get(key):
            return str(kwargs[key])
    ids = s.get("id") or []
    return str(ids[-1]) if ids else "langchain"


def _lc_msg(m: Any) -> Dict[str, Any]:
    role = getattr(m, "type", None) or type(m).__name__
    content = getattr(m, "content", m)
    out: Dict[str, Any] = {"role": role, "content": content}
    tc = getattr(m, "tool_calls", None)
    if tc:
        out["tool_calls"] = tc
    return out


def _lc_response(response: Any):
    text_parts = []
    usage: Dict[str, int] = {}
    try:
        for gen_list in getattr(response, "generations", []) or []:
            for gen in gen_list:
                msg = getattr(gen, "message", None)
                if msg is not None:
                    text_parts.append(str(getattr(msg, "content", "")))
                    um = getattr(msg, "usage_metadata", None) or {}
                    if um:
                        usage = {"input": int(um.get("input_tokens", 0)), "output": int(um.get("output_tokens", 0)),
                                 "total": int(um.get("total_tokens", 0))}
                else:
                    text_parts.append(str(getattr(gen, "text", "")))
        if not usage:
            lo = getattr(response, "llm_output", None) or {}
            tu = lo.get("token_usage") or lo.get("usage") or {}
            if tu:
                usage = {"input": int(tu.get("prompt_tokens", tu.get("input_tokens", 0)) or 0),
                         "output": int(tu.get("completion_tokens", tu.get("output_tokens", 0)) or 0)}
                usage["total"] = int(tu.get("total_tokens", usage["input"] + usage["output"]) or 0)
    except Exception:
        pass
    return "\n".join(t for t in text_parts if t), usage


def _lc_tool_output(output: Any) -> Any:
    c = getattr(output, "content", None)
    return c if c is not None else output


# ------------------------------------------------------------------ MCP (FastMCP)

def wrap_mcp(server: Any, policy: Any = None, agent: Optional[str] = None) -> Any:
    """Gate and record every tool call of a ``mcp.server.fastmcp.FastMCP`` server.

    >>> mcp = aiproof.wrap_mcp(FastMCP("crm-tools"))
    """
    from .client import guard

    g: Guard = guard(policy) if policy is not None else guard()
    original = server.call_tool
    server_name = getattr(server, "name", "mcp")

    async def call_tool(name: str, arguments: Dict[str, Any], *a: Any, **kw: Any):
        tool_name = f"{server_name}/{name}"
        g.tool_call(tool_name, arguments, agent=agent, gate_only=True)
        t0 = time.time()
        try:
            res = await original(name, arguments, *a, **kw)
        except BaseException as e:
            g.tool_call(tool_name, arguments, error=e, agent=agent, enforce=False,
                        latency_ms=int((time.time() - t0) * 1000))
            raise
        g.tool_call(tool_name, arguments, result=_mcp_result(res), agent=agent, enforce=False,
                    latency_ms=int((time.time() - t0) * 1000))
        return res

    server.call_tool = call_tool
    return server


def _mcp_result(res: Any) -> Any:
    try:
        if isinstance(res, (list, tuple)):
            return [getattr(b, "text", None) or getattr(b, "model_dump", lambda: str(b))() for b in res]
        return res
    except Exception:
        return str(res)
