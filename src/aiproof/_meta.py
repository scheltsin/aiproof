"""Single source of truth for project identity.

Everything user-visible (env vars, default file names, CLI name) derives from
``NAME`` so the project can be renamed with ``scripts/rename.py``.
"""

NAME = "aiproof"
VERSION = "0.1.0"

ENV_PREFIX = NAME.upper()  # AIPROOF_*
DEFAULT_DIR = f".{NAME}"  # ./.aiproof/
DEFAULT_LEDGER = "ledger.jsonl"
POLICY_FILE = f"{NAME}.json"  # ./aiproof.json
LEDGER_FORMAT = f"{NAME}/ledger/v0"
EVIDENCE_FORMAT = f"{NAME}/evidence/v0"
