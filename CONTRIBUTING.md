# Contributing

Good first contributions:

- **Control sets**: a JSON file under `src/aiproof/controls/` for another regulation (ISO 42001, NIST AI RMF, EU AI Act, ГОСТ Р 59276, industry rules). See `docs/spec/evidence-v0.md`.
- **Exact FSTEC 117 clause references** in `fstek_117.json` (`ref` field) with a link to the official text.
- **Detectors**: PII/identifier formats with validators (other CIS countries, industry ids). Add tests with valid and invalid checksums.
- **Filter rules**: injection patterns in Russian and English, always with a benign counter-example in `tests/test_filters.py` (false positives are bugs).
- **Integrations**: LangChain / LlamaIndex callbacks, MCP hooks, Go/JS ports of the ledger spec.

Contributor agreement: by submitting a pull request you assign the exclusive rights to your contribution to the project licensor (Arseniy Scheltsin) so the project can be relicensed as a whole (BSL 1.1 today, Apache-2.0 on the change date, commercial licenses). Add `Signed-off-by:` to your commits to confirm.

Rules: stdlib only in the core package (optional extras may depend on SDKs), no network calls from the library, every behaviour change comes with a test, `ruff check` clean, keep the "never break the host app" rule.

Run: `pip install -e ".[dev]" && pytest -q && ruff check src tests`.
