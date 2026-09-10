"""Minimal example: wrap an OpenAI-compatible client (GigaChat / YandexGPT /
Ollama / OpenAI all look the same) and get a verifiable ledger.

    pip install aiproof openai
    export OPENAI_API_KEY=...   # or the provider's key
    python examples/openai_basic.py
    aiproof verify .aiproof/ledger.jsonl
"""
import os

import aiproof
from openai import OpenAI

client = aiproof.wrap(
    OpenAI(base_url=os.environ.get("OPENAI_BASE_URL")),
    policy={"preset": "ru-fstek-117", "app": "example-bot", "tags": {"env": "dev"}},
)

resp = client.chat.completions.create(
    model=os.environ.get("MODEL", "gpt-4o-mini"),
    messages=[{"role": "user", "content": "Клиент с ИНН 7707083893 просит счёт. Что ответить?"}],
)
print(resp.choices[0].message.content)

# streaming works too; the record is written when the stream ends
for chunk in client.chat.completions.create(model=os.environ.get("MODEL", "gpt-4o-mini"),
                                            messages=[{"role": "user", "content": "Скажи привет"}], stream=True):
    print(chunk.choices[0].delta.content or "", end="")
print()
