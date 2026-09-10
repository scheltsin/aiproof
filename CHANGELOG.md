# Changelog

## 0.1.0 (unreleased)

- Hash-chained JSONL ledger with optional HMAC; `aiproof verify`.
- `wrap()`, `install()`, `record()`, local proxy for OpenAI-compatible APIs and Anthropic.
- PII / secret redaction, 25 detectors: ФИО, адрес, дата рождения, паспорт РФ, загранпаспорт, в/у, свидетельство о рождении, полис ОМС, ИНН, КПП, ОГРН/ОГРНИП, ОКПО, БИК, счёт, карта, CVV, IBAN, кадастровый номер, госномер, VIN, телефон, e-mail, IPv4, API keys (checksums where the id has one).
- Deterministic input/output filters (RU/EN), pluggable.
- `attest` / `check`: model inventory, pickle detection, datasets, dependencies, LLM call sites, agent config scan, AI-BOM (CycloneDX), signed evidence bundle.
- Control sets: FSTEC 117 (draft), 152-FZ, OWASP LLM Top 10 2025, EU AI Act, ISO 42001, NIST AI RMF; several per run; `aiproof controls`.
- Bilingual README (EN / RU).
- GitHub Action, Claude Code / Codex skill.
