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
from ._meta import NAME, VERSION as __version__
from .config import Policy, load_policy, PRESETS
from .core import Guard, Blocked
from .quota import QuotaExceeded
from .ledger import Ledger, verify_file
from .redact import redact, redact_obj, register as register_detector
from .filters import add_input_filter, add_output_filter, FilterFinding
from .client import wrap, install, uninstall, record, guard

__all__ = [
    "NAME", "__version__",
    "Policy", "load_policy", "PRESETS",
    "Guard", "Blocked", "QuotaExceeded",
    "Ledger", "verify_file",
    "redact", "redact_obj", "register_detector",
    "add_input_filter", "add_output_filter", "FilterFinding",
    "wrap", "install", "uninstall", "record", "guard",
]
