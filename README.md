# aiproof – LLM audit log, PII redaction and compliance evidence for AI apps and agents

**English** | [Русский](README.ru.md)

[![CI](https://github.com/aiproof/aiproof/actions/workflows/ci.yml/badge.svg)](https://github.com/aiproof/aiproof/actions)
[![PyPI](https://img.shields.io/pypi/v/aiproof)](https://pypi.org/project/aiproof/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](pyproject.toml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![No dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](pyproject.toml)

`aiproof` is an open-source **AI security and compliance toolkit for LLM applications**: a tamper-evident **audit log for every model call**, **prompt injection detection**, **PII and secret redaction** (25 detectors incl. Russian identifiers: ФИО, ИНН, СНИЛС, паспорт, ОМС, адрес, реквизиты), **usage quotas**, **AI-BOM** (CycloneDX ML-BOM) and a **signed evidence bundle** mapped to **FSTEC order 117 (AI section)**, with cross-references to **ISO/IEC 42001**, **NIST AI RMF**, **EU AI Act** and **OWASP Top 10 for LLM**.

Works with **OpenAI**, **Anthropic**, **GigaChat**, **YandexGPT**, **Ollama**, **vLLM**, **DeepSeek**, **OpenRouter** and any OpenAI-compatible API. Python 3.9+, zero dependencies, nothing leaves your machine.

```python
import aiproof
client = aiproof.wrap(OpenAI(base_url="https://gigachat.devices.sberbank.ru/api/v1"), policy="ru-fstek-117")
```

Two lines. Every prompt, response, tool call and error is now written to a hash-chained JSONL ledger, PII is masked before it hits disk, injection and leak findings are attached, quotas are enforced.

```
$ aiproof attest
  models 2  datasets 1  deps 14 (ai: openai, torch)  llm call sites 3  ledgers 1

Controls: ru-fstek-117
  PASS  AI-OP-01  Log every model request and response
  PASS  AI-OP-02  Tamper-evident event logs
  PASS  AI-OP-03  Input filtering (prompt injection, hidden content)
  FAIL  AI-DEV-02 No pickle-based model formats
  ...
evidence bundle: .aiproof/evidence-2026-09-10.zip (signed)
```

---

## Table of contents

- [Why aiproof](#why-aiproof)
- [Install](#install)
- [Quick start: three ways to integrate](#quick-start-three-ways-to-integrate)
- [Features](#features)
- [Ledger record format](#ledger-record-format)
- [Policy](#policy)
- [Prompt injection and leak filters](#prompt-injection-and-leak-filters)
- [Attest, check, verify: compliance evidence](#attest-check-verify-compliance-evidence)
- [CI/CD: GitHub Action, GitLab CI, Claude Code skill](#cicd-github-action-gitlab-ci-claude-code-skill)
- [Comparison with other tools](#comparison-with-other-tools)
- [FAQ](#faq)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Contributing and security](#contributing-and-security)

## Why aiproof

Regulators now require proof, not promises. In Russia the FSTEC methodology to order 117 (in force since 2026) applies to any information system using AI in the public sector, critical infrastructure, personal-data operators and their contractors, and demands logging of all model requests, input/output filtering, quotas, model-weight integrity and no pickle. The EU AI Act (Art. 12 record-keeping), ISO/IEC 42001 and NIST AI RMF ask for the same things in different words. There is no tooling; teams write it by hand and cannot prove the logs were not edited.

`aiproof` is the boring, auditable, open building block for that:

- an **append-only ledger** you can prove was not modified, reordered, truncated or regenerated;
- **deterministic, explainable filters** an auditor can read;
- an **inventory** of models, datasets, dependencies and LLM call sites;
- a **control map** that turns all of it into evidence, shipped as data (`src/aiproof/controls/*.json`).

It is **not an AI firewall** and does not compete with one. Put it behind any LLM gateway; it is the part that records and proves.

## Install

```
pip install aiproof
```

No dependencies. Python 3.9+. The OpenAI / Anthropic SDKs are optional extras (`pip install "aiproof[openai]"`).

## Quick start: three ways to integrate

**1. Wrap a client** (explicit, one place):

```python
import aiproof
from openai import OpenAI

client = aiproof.wrap(OpenAI(), policy="ru-fstek-117")
client.chat.completions.create(model="gpt-4o-mini", messages=[...])   # unchanged
```

Works with any OpenAI-compatible client (GigaChat, YandexGPT via OpenAI API, Ollama, vLLM, DeepSeek, OpenRouter, Mistral) and with `anthropic.Anthropic()`. Streaming and async are covered.

**2. Install once** (zero changes at call sites, Sentry-style):

```python
import aiproof
aiproof.install()   # patches openai / anthropic SDK classes in this process
```

**3. Local proxy** (no code at all):

```
aiproof proxy --upstream https://api.openai.com
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
```

And for anything else (local models, RAG pipelines, tool calls, custom HTTP):

```python
with aiproof.record("rag.answer", model="local-llm", input=question) as r:
    r.output = answer
    r.usage = {"input": 512, "output": 80}
```

## Features

| Area | What you get |
|---|---|
| **LLM audit log** | Hash-chained JSONL ledger (`prev` + SHA-256 + optional HMAC). Detects modification, reordering, deletion, chain regeneration without the key, tail truncation (with an external head). |
| **PII redaction** | 25 detectors: ФИО, адрес, дата рождения, паспорт РФ, загранпаспорт, водительское удостоверение, свидетельство о рождении, полис ОМС, ИНН, КПП, ОГРН/ОГРНИП, ОКПО, БИК, расчётный счёт, карты (Luhn), CVV, IBAN, кадастровый номер, госномер, VIN, телефон, e-mail, IPv4, API keys/JWT/private keys. Checksum-validated where the id has one, context-anchored otherwise, stable tokens, custom detectors. Full list: [docs/pii-detectors.md](docs/pii-detectors.md). |
| **Prompt injection detection** | RU + EN rules: instruction override, system-prompt extraction, stealth, disabling safety, exfiltration paths, dangerous shell, zero-width/bidi Unicode, HTML comments, fake chat delimiters. |
| **Output leak detection** | Secrets and PII in model responses; optional blocking. |
| **Quotas** | Requests per minute, tokens per day, prompt size. |
| **Storage modes** | `redacted` (default), `hash` (digests only), `none`. |
| **Attestation** | Model files (SHA-256, format by magic bytes, pickle detection), datasets, dependency pinning, LLM call sites without the wrapper, agent instruction files (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, MCP configs) with injected/hidden instructions. |
| **AI-BOM** | CycloneDX 1.6 with `machine-learning-model`, `data`, `library`, `service` components. |
| **Compliance evidence** | Signed zip: `attest.json`, `controls.json`, `aibom.json`, `policy.json`, ledgers, `manifest.json`. Verifiable offline. |
| **Control maps** | `ru-fstek-117`, `ru-152fz`, `owasp-llm-2025`, `eu-ai-act`, `iso-42001`, `nist-ai-rmf`; several at once (`--controls a,b`). Add your own as JSON. |
| **Never breaks the app** | Internal errors are recorded and swallowed unless `fail_closed`. Only quotas and explicit `block` actions stop a call. |

## Ledger record format

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

`hash` = SHA-256 of the canonical record; `prev` chains it to the previous one; `mac` = HMAC-SHA256 with `AIPROOF_KEY`. `aiproof verify` checks all three. The `sha256` inside `request`/`response` always covers the **original** content, so whoever holds the original can prove it matches the ledger even in `hash` storage mode. Spec: [docs/spec/ledger-v0.md](docs/spec/ledger-v0.md).

## Policy

`aiproof init` writes `aiproof.json`:

```json
{ "preset": "ru-fstek-117", "app": "support-bot", "store_content": "redacted", "tags": {"env": "prod"} }
```

Presets: `default`, `ru-fstek-117` (log everything, filter both ways, block secret leaks, quotas), `strict` (hash-only storage, block on injection, fail-closed). Every key can be overridden with `AIPROOF_<KEY>` environment variables; `aiproof policy ru-fstek-117` prints the effective values. Spec: [docs/spec/policy-v0.md](docs/spec/policy-v0.md).

## Prompt injection and leak filters

Deterministic rules, not a classifier: they catch the obvious, leave an audit trail an assessor can read, and give you a hook for the real thing:

```python
aiproof.add_input_filter(lambda request: my_gateway.scan(request))   # -> [FilterFinding]
aiproof.add_output_filter(my_dlp.scan)
aiproof.register_detector("contract_no", r"\bДОГ-\d{6}\b")           # custom PII token
```

Findings go to the ledger; `on_injection` / `on_secret_leak` decide whether to also block.

## Attest, check, verify: compliance evidence

```
aiproof attest [path]      # inventory + controls + evidence bundle (.zip)
aiproof check  [path]      # CI mode: exit 1 on FAIL or high/critical findings
aiproof verify ledger.jsonl | bundle.zip [--head <hash>]
aiproof controls           # list control sets
aiproof redact < file.txt  # try the redactor
```

Built-in control sets (`aiproof controls`):

| ID | Standard | Controls |
|---|---|---|
| `ru-fstek-117` | FSTEC of Russia, methodology to order 117, AI section (state systems, critical infrastructure, personal-data systems, contractors) | 15 |
| `ru-152fz` | Russian personal data law 152-FZ, technical part for PD sent to LLMs | 5 |
| `owasp-llm-2025` | OWASP Top 10 for LLM Applications 2025 | 10 |
| `eu-ai-act` | EU AI Act Art. 9–15, high-risk providers | 7 |
| `iso-42001` | ISO/IEC 42001:2023 Annex A | 7 |
| `nist-ai-rmf` | NIST AI RMF 1.0 + Generative AI Profile (AI 600-1) | 5 |

Run several at once: `aiproof attest --controls ru-fstek-117,owasp-llm-2025`. A custom set is a JSON file of the same shape passed by path. Candidates for contribution: ГОСТ Р 59276-2020, ГОСТ Р 56939-2024, FSTEC order 239 (critical infrastructure), Bank of Russia 683-P / GOST R 57580.1, MITRE ATLAS, CSA AI Controls Matrix, OWASP Agentic Top 10.

Control status semantics: `pass` (automated check ok), `fail`, `manual` (needs a human document: environment isolation, storage protection, monitoring regulation), `n/a`. Spec: [docs/spec/evidence-v0.md](docs/spec/evidence-v0.md). Control map: [docs/controls/fstek-117.md](docs/controls/fstek-117.md).

## CI/CD: GitHub Action, GitLab CI, Claude Code skill

GitHub:

```yaml
- uses: aiproof/aiproof@v0
  with:
    fail-on: fail        # fail | manual | never
```

GitLab (`.gitlab-ci.yml`): see [this repository's pipeline](.gitlab-ci.yml): lint, tests, `aiproof attest` with `evidence.zip` as an artifact.

Claude Code / Codex / Cursor: copy [`skills/aiproof/`](skills/aiproof/SKILL.md) into your skills directory and ask *"check this project for FSTEC 117 AI readiness"*.

## Comparison with other tools

| | aiproof | LLM observability (Langfuse, Arize, OpenLLMetry) | AI firewalls / gateways | Agent skill scanners (Snyk agent-scan, SkillSpector) |
|---|---|---|---|---|
| Tamper-evident audit log | yes (hash chain + HMAC) | no (mutable DB) | usually no | no |
| Russian PII redaction with checksums | yes | no | some | no |
| Prompt injection detection | rules, pluggable | no | yes (ML) | static only |
| Model / dataset / dependency inventory, AI-BOM | yes | no | no | partial |
| Control map to FSTEC 117 / ISO 42001 / EU AI Act | yes | no | no | no |
| Offline-verifiable evidence bundle | yes | no | no | no |
| Runs without a server | yes | no | no | yes |

Use them together: a gateway filters, an observability tool debugs, `aiproof` proves.

## FAQ

**How do I log all LLM requests for FSTEC order 117 (приказ ФСТЭК 117)?** Wrap the client or call `aiproof.install()`; the `ru-fstek-117` preset enables full logging, filters, quotas and PII minimisation. `aiproof attest` maps it to the controls.

**Does it work with GigaChat and YandexGPT?** Yes, through their OpenAI-compatible endpoints (set `base_url`) or through the local proxy. Provider is detected from the URL.

**Can I use it if we are not allowed to store prompts?** Set `store_content` to `hash`: only SHA-256 digests are kept, the chain still proves what was sent.

**Is my data sent anywhere?** No. Stdlib only, no network calls from the library. The proxy talks only to the upstream you configure.

**How is the ledger protected against an admin editing the file?** With `AIPROOF_KEY` every record carries an HMAC; without the key a rewritten chain fails `verify`. Ship the head hash (or the files) to a SIEM the application cannot write to.

**Does it slow down requests?** Redaction and rules on a typical prompt take well under a millisecond; the write is a single appended line.

**Will this pass a certification?** No tool does by itself. It produces the evidence and the gaps list; the manual controls need your documents. The FSTEC 117 map is a draft until clause references are verified.

## Limitations

- Filters are heuristics; chain a real classifier or gateway in `add_input_filter`.
- Quotas are per process; cluster-wide limits belong in your gateway.
- The FSTEC 117 control map is a **draft mapping** from the public methodology; verify clause numbers before a formal assessment.
- Ledger files grow; rotate with your log shipper and anchor heads externally.
- The proxy is stdlib and single-host: fine for dev, CI and small services.

## Roadmap

- v0.2: LangChain / LlamaIndex callbacks, MCP server/client hooks, Go SDK.
- v0.3: ISO 42001 and NIST AI RMF as first-class control maps; SARIF output for `check`.
- v0.4: evidence collector server (open API), SIEM / ГосСОПКА exporters.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). License: Apache-2.0.

---

### Кратко по-русски

`aiproof` – открытая библиотека **безопасности и соответствия для LLM-приложений и ИИ-агентов**: неизменяемый **журнал всех запросов к модели** (цепочка хешей + HMAC), **маскирование персональных данных** (ИНН, СНИЛС, паспорт, телефон, счёт, карта) с проверкой контрольных сумм, **детектор prompt injection** на русском и английском, **квоты**, **AI-BOM** и **подписанный пакет доказательств** по требованиям **приказа ФСТЭК № 117** (раздел ИИ), с привязкой к ISO 42001, NIST AI RMF, EU AI Act и OWASP LLM Top 10. Работает с GigaChat, YandexGPT, OpenAI, Anthropic, Ollama и любым OpenAI-совместимым API. Две строки кода, ноль зависимостей, данные не покидают ваш контур. Полное описание: [README.ru.md](README.ru.md).
