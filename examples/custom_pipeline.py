"""Record anything: a local model, a RAG step, a tool call, an approval.

Run:  python examples/custom_pipeline.py && aiproof verify
"""
import aiproof

g = aiproof.guard({"preset": "ru-fstek-117", "app": "rag-demo"})

question = "Какой срок действия договора у клиента с ИНН 7707083893?"

with aiproof.record("rag.retrieve", model="bge-m3", input=question, k=5) as r:
    r.output = ["doc-12 §3.1", "doc-7 §1"]  # ids only, no content needed

with aiproof.record("rag.answer", model="local-llama-3.1-8b", input={"q": question, "ctx": ["…"]}) as r:
    r.output = "Договор действует до 31.12.2026 (doc-12 §3.1)."
    r.usage = {"input": 640, "output": 42}

# arbitrary application events land in the same chain
g.event("tool.call", tool="crm.update", args={"inn": "7707083893", "field": "status"}, approved_by="user:42")
print("ledger head:", g.ledger.head())
