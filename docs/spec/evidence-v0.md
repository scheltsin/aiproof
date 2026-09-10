# Evidence bundle `aiproof/evidence/v0`

A zip file an auditor can verify without access to the system that produced it.

```
evidence-2026-09-10.zip
├── manifest.json     # hashes of every file below, bundle hash, optional HMAC
├── attest.json       # raw inventory: models, datasets, deps, LLM call sites, agent files, ledgers, findings
├── controls.json     # control set id + per-control status (pass/fail/manual/n/a) + which checks and evidence back it
├── aibom.json        # CycloneDX 1.6, components of type machine-learning-model / data / library / service
├── policy.json       # the policy file in force (if present)
└── ledger/*.jsonl    # the ledgers themselves (optional, --no-ledgers)
```

`manifest.json`:

```json
{"fmt":"aiproof/evidence/v0","lib":"aiproof/0.1.0","ts":"…","app":"support-bot",
 "controls_id":"ru-fstek-117","summary":{"pass":8,"fail":2,"manual":5,"n/a":0},
 "files":{"attest.json":{"sha256":"…","size":1234}, …},
 "hash":"<sha256 of canonical manifest without hash/mac>","mac":"<hmac>"}
```

Verification (`aiproof verify bundle.zip`): manifest hash; MAC if a key is given; every listed file present with the listed digest; every ledger inside passes ledger verification.

## Control status semantics

- `pass`: all automated checks for the control passed.
- `fail`: at least one automated check failed. `notes` says which.
- `manual`: the control needs a human-provided document (environment isolation, storage protection…). The bundle records that it is required; the assessor attaches the document alongside.
- `n/a`: the control does not apply to this repository (no model files, no LLM code).

## Control sets

A control set is a JSON file (`src/aiproof/controls/<id>.json`) listing controls with `checks` (ids evaluated by `attest.evaluate_checks`) and `evidence` (which bundle artifacts back it). Anyone can add a set for another regulation without touching code; pass a path with `--controls my-set.json`.
