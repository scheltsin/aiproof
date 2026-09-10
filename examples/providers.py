"""The same wrapper line for every provider. Set the provider's API key in the
usual environment variable (OPENAI_API_KEY, ANTHROPIC_API_KEY, ...) and run:

    python examples/providers.py gigachat | yandexgpt | openai | ollama | vllm | deepseek | openrouter | anthropic
"""
import os
import sys

import aiproof

PROVIDERS = {
    # name: (base_url, default model, api_key env var)
    "openai":     (None, "gpt-4o-mini", "OPENAI_API_KEY"),
    "gigachat":   ("https://gigachat.devices.sberbank.ru/api/v1", "GigaChat", "GIGACHAT_ACCESS_TOKEN"),
    "yandexgpt":  ("https://llm.api.cloud.yandex.net/v1", f"gpt://{os.environ.get('YC_FOLDER_ID', '<folder>')}/yandexgpt/latest", "YC_API_KEY"),
    "ollama":     ("http://localhost:11434/v1", "llama3.1", None),
    "vllm":       ("http://localhost:8000/v1", "Qwen/Qwen2.5-7B-Instruct", None),
    "deepseek":   ("https://api.deepseek.com", "deepseek-chat", "DEEPSEEK_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "openai/gpt-4o-mini", "OPENROUTER_API_KEY"),
}

name = sys.argv[1] if len(sys.argv) > 1 else "ollama"
policy = {"preset": "ru-fstek-117", "app": f"providers-demo-{name}"}
prompt = "Клиент Иванов Иван Иванович, ИНН 7707083893, просит выставить счёт. Что ответить?"

if name == "anthropic":
    from anthropic import Anthropic
    client = aiproof.wrap(Anthropic(), policy=policy)
    msg = client.messages.create(model="claude-sonnet-4-5", max_tokens=200,
                                 messages=[{"role": "user", "content": prompt}])
    print(msg.content[0].text)
else:
    from openai import OpenAI
    base_url, model, key_var = PROVIDERS[name]
    api_key = os.environ.get(key_var) if key_var else "local"
    client = aiproof.wrap(OpenAI(base_url=base_url, api_key=api_key), policy=policy)
    resp = client.chat.completions.create(model=os.environ.get("MODEL", model),
                                          messages=[{"role": "user", "content": prompt}])
    print(resp.choices[0].message.content)

print("\nledger:", aiproof.guard().policy.ledger_path, "-> run: aiproof verify")
