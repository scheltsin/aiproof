"""aiproof: tamper-evident audit trail, Russian PII redaction, quotas and
compliance evidence for LLM apps and agents.

Two lines::

    import aiproof
    client = aiproof.wrap(OpenAI(), policy="ru-fstek-117")

Or zero lines at call sites::

    aiproof.install()          # patches the OpenAI / Anthropic SDKs in-process

Anything else::

    with aiproof.record("rag.answer", model="local-llm", input=q) as r:
        r.output = answer
"""
from ._meta import NAME
from ._meta import VERSION as __version__
from .client import guard, install, record, uninstall, wrap
from .config import PRESETS, Policy, load_policy
from .core import Blocked, Guard
from .filters import FilterFinding, add_input_filter, add_output_filter
from .ledger import Ledger, verify_file
from .quota import QuotaExceeded
from .redact import redact, redact_obj
from .redact import register as register_detector

__all__ = [
    "NAME",
    "PRESETS",
    "Blocked",
    "FilterFinding",
    "Guard",
    "Ledger",
    "Policy",
    "QuotaExceeded",
    "__version__",
    "add_input_filter",
    "add_output_filter",
    "guard",
    "install",
    "load_policy",
    "record",
    "redact",
    "redact_obj",
    "register_detector",
    "uninstall",
    "verify_file",
    "wrap",
]
