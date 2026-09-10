# Ledger format `aiproof/ledger/v0`

Status: draft. Any implementation (any language) that follows this document produces ledgers that `aiproof verify` accepts, and vice versa.

## File

UTF-8 JSON Lines. One JSON object per line, append-only. Rotation (default at 256 MB) renames the full file to `<stem>-<utc>-<seq>.jsonl` and continues in a fresh file whose first record carries `prev` = last hash of the previous file and the next `seq`; `prev` = 64 zeros marks the start of a chain. Several processes may append to one file: writers take an advisory lock and re-read the tail before appending.

## Record

Required keys:

| key | type | meaning |
|---|---|---|
| `fmt` | string | `"aiproof/ledger/v0"` |
| `seq` | int | 1-based, strictly increasing by 1 within a file |
| `ts` | string | UTC, `YYYY-MM-DDTHH:MM:SS.mmmZ` |
| `app` | string | logical system id |
| `event` | string | `llm.call`, `aiproof.error`, or any application event (`tool.call`, `approval`, …) |
| `prev` | hex | `hash` of the previous record, or `"0"*64` |
| `lib` | string | producer, `name/version` |
| `hash` | hex | SHA-256 over the canonical JSON of the record without `hash` and `mac` |

Optional: `mac` (hex) = HMAC-SHA256(key, `hash`) where `key` is the raw bytes of the shared secret.

Canonical JSON: keys sorted, separators `,` and `:` without spaces, `ensure_ascii=false`, UTF-8.

## `llm.call` payload

| key | type | notes |
|---|---|---|
| `call_id` | string | uuid |
| `provider` | string | `openai`, `anthropic`, `openai-compatible/<name>`, `custom` |
| `op` | string | `chat.completions`, `responses`, `messages`, `embeddings`, or free-form |
| `model` | string | |
| `status` | string | `ok`, `error`, `blocked` |
| `latency_ms` | int | |
| `policy` | string | policy name |
| `request` | content view | see below |
| `response` | content view | only when `status=ok` |
| `usage` | `{input,output,total}` | ints, when known |
| `error` | string | when `status` is `error`/`blocked` |
| `findings` | `{input:[…], output:[…]}` | filter findings `{rule, severity, category, snippet}` |
| `severity` | string | max severity of findings |
| `tags`, `meta` | object | policy tags / call metadata |

Content view: `{"sha256": <digest of canonical original>, "data": <redacted content>, "pii": {<type>: count}, "truncated": bool}`. `data` and `pii` are omitted when `store_content` is `hash` or `none`. The digest always covers the **original** (unredacted) content, so a party that holds the original can prove it matches the ledger without the ledger holding the data.

## Verification

For each record in order: `seq` == previous+1; `prev` == previous `hash`; `hash` == SHA-256(canonical(record − {hash, mac})); if a key is supplied, `mac` == HMAC(key, hash). Optionally compare the final hash with an expected head (published elsewhere: a SIEM, a git commit, a timestamping service) to detect truncation of the tail.

## Threat model

Protects against silent modification, reordering and deletion inside the file, and, with a key, against re-generation of the chain by someone who can write the file but does not hold the key. Does not protect against deletion of the whole file or truncation of the tail without an external head anchor; ship heads (or the files) to a system the application cannot write to.
