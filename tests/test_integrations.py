import json

import pytest

import aiproof
from aiproof.core import Guard
from aiproof.integrations import LLM_PATH, response_text, response_usage, wrap_positional


def records(path):
    return [json.loads(line) for line in open(path, encoding="utf-8")]


def test_llm_path_matching():
    yes = ["/v1/chat/completions", "/foundationModels/v1/completion", "/api/chat", "/api/generate",
           "/api/v1/chat/completions", "/v1/messages", "/v1/embeddings", "/completions?x=1"]
    no = ["/health", "/v1/models", "/api/users", "/chat", "/completionsx"]
    for p in yes:
        assert LLM_PATH.search(p.split("?")[0] + "?"), p
    for p in no:
        assert not LLM_PATH.search(p.split("?")[0] + "?"), p


def test_yandex_and_ollama_parsing():
    y = {"result": {"alternatives": [{"message": {"role": "assistant", "text": "привет"}}],
                    "usage": {"inputTextTokens": "7", "completionTokens": "5", "totalTokens": "12"}}}
    assert response_text(y) == "привет" and response_usage(y) == {"input": 7, "output": 5, "total": 12}
    o = {"message": {"role": "assistant", "content": "hi"}, "prompt_eval_count": 4, "eval_count": 3}
    assert response_usage(o) == {"input": 4, "output": 3, "total": 7}


def test_wrap_positional_and_nested_dedupe(tmp_path):
    g = Guard({"preset": "ru-fstek-117", "app": "t", "ledger_path": str(tmp_path / "l.jsonl")})

    class Resp:
        def model_dump(self):
            return {"choices": [{"message": {"content": "ok"}}], "usage": {"total_tokens": 3}}

    def inner(payload):
        return Resp()

    inner_w = wrap_positional(inner, g, "gigachat", "chat", lambda: "GigaChat")

    def outer(payload):  # like SDK chat() calling _chat()
        return inner_w(payload)

    outer_w = wrap_positional(outer, g, "gigachat", "chat", lambda: "GigaChat")
    outer_w({"messages": [{"role": "user", "content": "ИНН 7707083893"}]})
    recs = records(str(tmp_path / "l.jsonl"))
    assert len(recs) == 1 and recs[0]["model"] == "GigaChat" and recs[0]["request"]["pii"] == {"inn": 1}


@pytest.mark.skipif(pytest.importorskip("httpx", reason="httpx not installed") is None, reason="httpx")
def test_httpx_hook_records_llm_calls_only(tmp_path):
    import httpx
    aiproof.install(policy={"preset": "ru-fstek-117", "app": "t", "ledger_path": str(tmp_path / "l.jsonl")}, http=True)
    try:
        def handler(request):
            if request.url.path.endswith("/api/chat"):
                return httpx.Response(200, json={"message": {"content": "hi a@b.ru"}, "prompt_eval_count": 1, "eval_count": 2})
            return httpx.Response(200, json={"ok": True})
        with httpx.Client(transport=httpx.MockTransport(handler)) as c:
            c.post("http://ollama.local:11434/api/chat", json={"model": "llama3.1", "messages": [{"role": "user", "content": "x"}]})
            c.get("http://ollama.local:11434/health")
    finally:
        aiproof.uninstall()
    recs = records(str(tmp_path / "l.jsonl"))
    assert len(recs) == 1
    assert recs[0]["provider"] == "http/ollama" and recs[0]["model"] == "llama3.1"
    assert recs[0]["usage"]["total"] == 3 and "a@b.ru" not in json.dumps(recs[0])
