# Policy file `aiproof.json`

```json
{
  "preset": "ru-fstek-117",
  "app": "support-bot",
  "ledger_path": ".aiproof/ledger.jsonl",
  "store_content": "redacted",
  "max_content_chars": 20000,
  "rotate_mb": 256,
  "tags": {"env": "prod", "owner": "team-x"},
  "redact": true,
  "redact_types": ["inn","snils","ogrn","passport_rf","phone_ru","email","card","bank_account","secret"],
  "filter_input": true,
  "filter_output": true,
  "on_injection": "log",
  "on_secret_leak": "block",
  "max_requests_per_minute": 3000,
  "max_tokens_per_day": 0,
  "max_prompt_chars": 0,
  "fail_closed": false,
  "enabled": true
}
```

Resolution order: preset → file → `policy=` argument (name or dict) → `AIPROOF_*` environment variables. The HMAC key is never stored in the file; use `AIPROOF_KEY`.

Env examples: `AIPROOF_APP=support-bot`, `AIPROOF_STORE_CONTENT=hash`, `AIPROOF_ON_INJECTION=block`, `AIPROOF_PRESET=strict`, `AIPROOF_LEDGER_PATH=/var/log/aiproof/ledger.jsonl`, `AIPROOF_ENABLED=false`.
