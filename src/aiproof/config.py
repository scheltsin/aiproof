"""Policy configuration.

A policy is a plain dict-like object. It can come from (in priority order):

1. explicit ``Policy(...)`` / ``policy=`` argument,
2. environment variables ``<NAME>_*``,
3. ``./aiproof.json`` (or the path in ``<NAME>_POLICY``),
4. a preset name (``"default"``, ``"ru-fstek-117"``, ``"strict"``).

Design rule: **never break the host application**. Unknown keys are ignored,
missing files fall back to the ``default`` preset, and every failure inside the
library is swallowed unless ``fail_closed`` is set.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from ._meta import ENV_PREFIX, DEFAULT_DIR, DEFAULT_LEDGER, POLICY_FILE, NAME


@dataclass
class Policy:
    """Runtime policy for the wrapper, ledger, redaction, filters and quotas."""

    # identity
    name: str = "default"
    app: str = "app"  # logical application / system id (shows up in every record)

    # ledger
    ledger_path: str = os.path.join(DEFAULT_DIR, DEFAULT_LEDGER)
    # what to store about prompts/responses: "redacted" | "hash" | "none"
    store_content: str = "redacted"
    max_content_chars: int = 20000  # truncate very long content (hash is always full)
    # HMAC key (hex/utf-8) for authenticating the chain. Read from env <NAME>_KEY if empty.
    key: Optional[str] = None
    # extra metadata copied into every record (e.g. {"env": "prod", "owner": "team-x"})
    tags: Dict[str, str] = field(default_factory=dict)

    # redaction (Russian + generic PII / secrets)
    redact: bool = True
    # detector names (see `aiproof redact --types`); ["*"] = all built-in and registered detectors
    redact_types: List[str] = field(default_factory=lambda: ["*"])

    # filters
    filter_input: bool = True
    filter_output: bool = True
    # what to do on a finding: "log" | "block"
    on_injection: str = "log"
    on_secret_leak: str = "log"

    # quotas (0 = unlimited)
    max_requests_per_minute: int = 0
    max_tokens_per_day: int = 0
    max_prompt_chars: int = 0

    # behaviour
    fail_closed: bool = False  # True: any internal error stops the LLM call
    enabled: bool = True

    # ------------------------------------------------------------------ helpers
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("key", None)  # never serialise the key
        return d

    def hmac_key(self) -> Optional[bytes]:
        k = self.key or os.environ.get(f"{ENV_PREFIX}_KEY")
        if not k:
            return None
        return k.encode("utf-8")


PRESETS: Dict[str, Dict[str, Any]] = {
    "default": {},
    # Aligned with the FSTEC methodology to order 117 (AI section): log every
    # request, filter inputs/outputs, quotas, PII minimisation.
    "ru-fstek-117": {
        "name": "ru-fstek-117",
        "store_content": "redacted",
        "redact": True,
        "filter_input": True,
        "filter_output": True,
        "on_injection": "log",
        "on_secret_leak": "block",
        "max_requests_per_minute": 600,
        "max_tokens_per_day": 0,
    },
    # Same as ru-fstek-117 but blocks on injection and stores hashes only.
    "strict": {
        "name": "strict",
        "store_content": "hash",
        "on_injection": "block",
        "on_secret_leak": "block",
        "fail_closed": True,
        "max_requests_per_minute": 300,
    },
}

_BOOL_KEYS = {"redact", "filter_input", "filter_output", "fail_closed", "enabled"}
_INT_KEYS = {"max_requests_per_minute", "max_tokens_per_day", "max_prompt_chars", "max_content_chars"}


def _coerce(key: str, value: str) -> Any:
    if key in _BOOL_KEYS:
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if key in _INT_KEYS:
        try:
            return int(value)
        except ValueError:
            return 0
    if key == "redact_types":
        return [v.strip() for v in value.split(",") if v.strip()]
    if key == "tags":
        try:
            return json.loads(value)
        except Exception:
            return {}
    return value


def _apply(policy: Policy, data: Dict[str, Any]) -> Policy:
    for k, v in (data or {}).items():
        if hasattr(policy, k) and k != "key":
            setattr(policy, k, v)
    if "key" in (data or {}):
        policy.key = data["key"]
    return policy


def load_policy(source: Any = None, search_cwd: bool = True) -> Policy:
    """Resolve a policy from a preset name, a file path, a dict, a Policy or nothing."""
    if isinstance(source, Policy):
        return source

    policy = Policy()

    # 1. project file
    file_path = os.environ.get(f"{ENV_PREFIX}_POLICY")
    if not file_path and search_cwd and Path(POLICY_FILE).is_file():
        file_path = POLICY_FILE
    if isinstance(source, (str, os.PathLike)) and Path(source).is_file():
        file_path = str(source)
        source = None
    if file_path:
        try:
            data = json.loads(Path(file_path).read_text(encoding="utf-8"))
            preset = data.get("preset")
            if preset in PRESETS:
                _apply(policy, PRESETS[preset])
            _apply(policy, data)
        except Exception:
            pass  # never break the host app on a bad policy file

    # 2. preset / dict argument
    if isinstance(source, str):
        if source in PRESETS:
            _apply(policy, PRESETS[source])
            policy.name = source
        else:
            policy.name = source
    elif isinstance(source, dict):
        preset = source.get("preset")
        if preset in PRESETS:
            _apply(policy, PRESETS[preset])
        _apply(policy, source)

    # 3. environment overrides: AIPROOF_APP, AIPROOF_LEDGER_PATH, AIPROOF_STORE_CONTENT ...
    for env_key, value in os.environ.items():
        if not env_key.startswith(ENV_PREFIX + "_"):
            continue
        attr = env_key[len(ENV_PREFIX) + 1:].lower()
        if attr in {"key", "policy"}:
            continue
        if attr == "preset" and value in PRESETS:
            _apply(policy, PRESETS[value])
            policy.name = value
            continue
        if hasattr(policy, attr):
            setattr(policy, attr, _coerce(attr, value))

    return policy


def write_policy_file(path: str = POLICY_FILE, preset: str = "ru-fstek-117", app: str = "app") -> str:
    """Create a starter policy file. Used by ``aiproof init``."""
    data = {
        "$schema": f"https://github.com/{NAME}/{NAME}/blob/main/docs/spec/policy-v0.md",
        "preset": preset,
        "app": app,
        "store_content": "redacted",
        "tags": {"env": "dev"},
    }
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path
