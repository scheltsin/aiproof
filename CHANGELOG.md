# Changelog

## 0.2.0 (2026-10-04)

Regulatory and standards update:

- FSTEC 117 control map v1.1: references to order 117 as amended by order 137 of 08.05.2026 (p. 60–61: dedicated AI segment, strengthened MFA, least privilege, filtering, quotas, functionality control), the draft amendment #170500 (AI agents incl. autonomous, in force 01.03.2027) as `проект-2027` controls AI-AGT-01/02, and the maturity assessment methodology of 07.08.2026.
- New control sets: `owasp-llm-2026` (new 2026 numbering: Excessive Agency #3, Hidden Context Exposure), `owasp-agentic-2026` (ASI01–ASI10), `ru-243fz` (federal AI law 243-ФЗ of 26.07.2026).

Agents:

- Tool policy: `allowed_tools` (fnmatch allowlist) and `tools_require_approval` in the policy; `aiproof.record_tool()`, `@aiproof.tool()` decorator (sync/async) with gate-before / record-after; `tool.call` ledger events with redacted arguments, decision and `approved_by`.
- `aiproof.langchain_handler()` callback for LangChain / LangGraph (LLM calls + tools), `aiproof.wrap_mcp()` for FastMCP servers.
- AgBOM: MCP servers from `.mcp.json` / `claude_desktop_config.json` / `mcp.json` and agent tools seen in ledgers become CycloneDX components; `mcp.remote_server` finding; new checks `policy.tools_allowlist`, `policy.tools_approval`, `ledger.tool_events`, `mcp.inventoried`, `mcp.no_remote`.

Exports:

- `aiproof export --format otel|ocsf|cef`: OpenTelemetry GenAI attributes, OCSF API Activity (6003), CEF for KUMA / MaxPatrol SIEM / Splunk.
- `aiproof check --sarif report.sarif` for GitHub code scanning / GitLab SAST.

CI: Python 3.14 in the matrix.


## 0.1.0 (unreleased)

- Hash-chained JSONL ledger with optional HMAC; rotation at `rotate_mb` with chain continuity across segments; multi-process safe appends (advisory lock); `aiproof verify` for files, directories and bundles.
- Redaction performance: regex prefilters and per-string cache (about 0.6 ms per call with all detectors).
- `wrap()`, `install()`, `record()`, local proxy for OpenAI-compatible APIs and Anthropic.
- PII / secret redaction, 25 detectors: ФИО, адрес, дата рождения, паспорт РФ, загранпаспорт, в/у, свидетельство о рождении, полис ОМС, ИНН, КПП, ОГРН/ОГРНИП, ОКПО, БИК, счёт, карта, CVV, IBAN, кадастровый номер, госномер, VIN, телефон, e-mail, IPv4, API keys (checksums where the id has one).
- Deterministic input/output filters (RU/EN), pluggable.
- `attest` / `check`: model inventory, pickle detection, datasets, dependencies, LLM call sites, agent config scan, AI-BOM (CycloneDX), signed evidence bundle.
- Control sets: FSTEC 117 (v1.0, quotes the methodological document of 12.04.2026 p. 3.18, 27 controls incl. enhancements), 152-FZ, OWASP LLM Top 10 2025, EU AI Act, ISO 42001, NIST AI RMF; several per run; `aiproof controls`.
- Bilingual README (EN / RU); GitHub listing and Marketplace copy in docs/github-listing.md.
- CI on Node 24 actions, Python 3.9–3.13, action smoke test; release workflow (GitHub Release + PyPI trusted publishing).
- Integrations for closed contours: official gigachat SDK wrapper, `install(http=True)` for requests/httpx (YandexGPT Foundation Models API, GigaChat REST, Ollama, vLLM), foreign-SaaS detection in `check`.
- License: Business Source License 1.1 (free for non-commercial, government, evaluation; commercial license for production use by for-profit organisations; Apache-2.0 after four years).
- GitHub Action, Claude Code / Codex skill.
