# aiproof

**Tamper-evident audit trail, Russian PII redaction, quotas and compliance evidence for LLM apps and agents. Two lines to integrate. Nothing leaves your machine.**

```python
import aiproof
client = aiproof.wrap(OpenAI(base_url="https://gigachat.devices.sberbank.ru/api/v1"), policy="ru-fstek-117")
```

That is the whole integration. From now on every prompt, response, tool call and error is written to a hash-chained JSONL ledger with Russian PII (ИНН, СНИЛС, паспорт, телефон, реквизиты, карты) masked before it hits disk, prompt-injection and secret-leak findings attached, and per-process quotas enforced.

Then, when security or a customer asks *«покажите, как у вас с безопасностью ИИ по 117-му приказу»*:

```
$ aiproof attest
  models 2  datasets 1  deps 14 (ai: openai, torch)  llm call sites 3  ledgers 1

Controls: ru-fstek-117
  PASS  AI-OP-01  Регистрация всех запросов к модели и ответов модели
  PASS  AI-OP-02  Целостность и неизменность журналов событий ИИ
  PASS  AI-OP-03  Фильтрация входных данных (запросов) к модели
  FAIL  AI-DEV-02 Запрет небезопасных форматов сериализации моделей (pickle)
  ...
evidence bundle: .aiproof/evidence-2026-09-10.zip (signed)
```

The bundle (ledger + AI-BOM + control map + manifest) can be verified offline by an auditor with `aiproof verify bundle.zip`, without access to your system.

---

## Why

Since 2026 the FSTEC methodology to order 117 applies to any information system using AI in the Russian public sector, critical infrastructure, personal-data operators and their contractors. It requires, among other things: logging of all model requests, input/output filtering, quotas, model-weight integrity, no pickle. There is no certification methodology and no tooling; teams write this by hand.

`aiproof` is the boring, auditable, open building block for that: an append-only ledger you can prove was not edited, deterministic filters you can explain, an inventory of models and dependencies, and a control map that turns all of it into evidence. The control map is data (`src/aiproof/controls/*.json`); FSTEC 117 ships first, ISO 42001 / NIST AI RMF / EU AI Act cross-references are already in the rows.

It is **not** an AI firewall and does not compete with one. Put it behind any gateway; it is the part that records and proves.

## Install

```
pip install aiproof
```

No dependencies. Python 3.9+. The OpenAI / Anthropic SDKs are optional.

## Three ways to integrate

**1. Wrap a client** (explicit, one place):

```python
import aiproof
from openai import OpenAI

client = aiproof.wrap(OpenAI(), policy="ru-fstek-117")
client.chat.completions.create(model="gpt-4o-mini", messages=[...])   # unchanged
```

Works with any OpenAI-compatible client (GigaChat, YandexGPT via OpenAI API, Ollama, vLLM, DeepSeek, OpenRouter) and with `anthropic.Anthropic()`. Streaming and async are covered.

**2. Install once** (zero changes at call sites):

```python
import aiproof
aiproof.install()   # patches openai / anthropic SDK classes in this process
```

**3. Proxy** (no code at all):

```
aiproof proxy --upstream https://api.openai.com
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
```

And for anything else (local models, RAG, tools, custom HTTP):

```python
with aiproof.record("rag.answer", model="local-llm", input=question) as r:
    r.output = answer
    r.usage = {"input": 512, "output": 80}
```

## What a ledger record looks like

```json
{"fmt":"aiproof/ledger/v0","seq":42,"ts":"2026-09-10T12:00:01.512Z","app":"support-bot",
 "event":"llm.call","prev":"6f1c…","lib":"aiproof/0.1.0",
 "call_id":"…","provider":"openai-compatible/gigachat","op":"chat.completions","model":"GigaChat-Pro",
 "status":"ok","latency_ms":840,"policy":"ru-fstek-117",
 "request":{"sha256":"…","data":{"messages":[{"role":"user","content":"Клиент <INN:c202>, тел <PHONE_RU:3e9c> …"}]},"pii":{"inn":1,"phone_ru":1}},
 "response":{"sha256":"…","data":"…"},
 "usage":{"input":231,"output":88,"total":319},
 "findings":{"input":[{"rule":"inj.override.ru","severity":"high","category":"injection","snippet":"…"}]},
 "severity":"high",
 "hash":"a41b…","mac":"9c0e…"}
```

`hash` = SHA-256 of the canonical record; `prev` chains it to the previous one; `mac` = HMAC-SHA256 with `AIPROOF_KEY`, so nobody without the key can rewrite history even if they recompute every hash. `aiproof verify` checks all three. Spec: [docs/spec/ledger-v0.md](docs/spec/ledger-v0.md).

Content storage is a policy choice: `"redacted"` (default), `"hash"` (only digests, for teams that cannot store prompts) or `"none"`.

## Policy

`aiproof init` writes `aiproof.json`:

```json
{ "preset": "ru-fstek-117", "app": "support-bot", "store_content": "redacted", "tags": {"env": "prod"} }
```

Presets: `default`, `ru-fstek-117` (log everything, filter both ways, block secret leaks, quotas), `strict` (hash-only storage, block on injection, fail-closed). Every key can be overridden with `AIPROOF_<KEY>` environment variables. `aiproof policy ru-fstek-117` prints the effective values.

Behaviour rule: **the library never breaks your app.** Internal errors are recorded and swallowed unless `fail_closed` is set. The only things that stop a call are quotas and explicit `block` actions in your policy.

## Filters

Deterministic rules, RU + EN: instruction override, system-prompt extraction, stealth ("do not tell the user"), disabling safety, secret exfiltration paths (`~/.ssh`, `.env`, tokens), network exfil (`curl … | sh`), dangerous shell, hidden content (zero-width and bidi Unicode, HTML comments, fake chat delimiters), and secret/PII leakage in outputs. Findings go to the ledger; `on_injection` / `on_secret_leak` decide whether to also block.

Plug your own (a classifier, your AI gateway, anything):

```python
aiproof.add_input_filter(lambda request: my_gateway.scan(request))   # -> [FilterFinding]
aiproof.register_detector("contract_no", r"\bДОГ-\d{6}\b")           # custom PII token
```

## Attest, check, verify

```
aiproof attest [path]      # inventory + controls + evidence bundle (.zip)
aiproof check  [path]      # same, CI mode: exit 1 on FAIL or high/critical findings
aiproof verify ledger.jsonl | bundle.zip
```

`attest` finds: model files (sha256, format, pickle detection by magic bytes), dataset files, dependency manifests and lock files, LLM call sites without the wrapper, agent instruction files (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, MCP configs) with hidden or injected instructions, and ledgers, which it verifies. Output: `attest.json`, `aibom.json` (CycloneDX 1.6 ML-BOM), `controls.json`, `manifest.json`. Spec: [docs/spec/evidence-v0.md](docs/spec/evidence-v0.md).

GitHub Action:

```yaml
- uses: aiproof/aiproof@v0
  with:
    fail-on: fail        # fail | manual | never
```

Claude Code / Codex skill: copy `skills/aiproof/` into your skills directory and ask *«проверь проект на готовность к ФСТЭК 117 по ИИ»*.

## Limitations (read this)

- Filters are heuristics. They catch the obvious and leave an audit trail; they are not a classifier and will miss creative attacks. Chain a real gateway in `add_input_filter`.
- Quotas are per process. Cluster-wide limits belong in your gateway.
- The FSTEC 117 control map is a **draft mapping** made from the public methodology; clause numbers must be checked against the official text before you rely on it in an assessment (`docs/controls/fstek-117.md`).
- Ledger files grow; rotate them with your log shipper. A rotated file is still verifiable on its own; pass `--head` to detect truncation.
- The proxy is stdlib and single-host. Fine for dev, CI and small services.

## Roadmap

- v0.2: LangChain / LlamaIndex callbacks, MCP server/client hooks, Go SDK.
- v0.3: ISO 42001 and NIST AI RMF control sets as first-class maps; SARIF output for `check`.
- v0.4: evidence collector server (open API), SIEM/ГосСОПКА exporters.

## Contributing / security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Apache-2.0.
