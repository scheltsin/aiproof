# Changelog

## 0.1.0 (unreleased)

- Hash-chained JSONL ledger with optional HMAC; `aiproof verify`.
- `wrap()`, `install()`, `record()`, local proxy for OpenAI-compatible APIs and Anthropic.
- Russian PII / secret redaction with checksum validation (ИНН, СНИЛС, ОГРН/ОГРНИП, паспорт РФ, телефон, счёт, карта, e-mail, API keys).
- Deterministic input/output filters (RU/EN), pluggable.
- `attest` / `check`: model inventory, pickle detection, datasets, dependencies, LLM call sites, agent config scan, AI-BOM (CycloneDX), signed evidence bundle.
- Control sets: FSTEC 117 (draft), 152-FZ, OWASP LLM Top 10 2025, EU AI Act, ISO 42001, NIST AI RMF; several per run; `aiproof controls`.
- Bilingual README (EN / RU).
- GitHub Action, Claude Code / Codex skill.
