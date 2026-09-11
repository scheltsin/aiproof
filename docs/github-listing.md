# GitHub: описание репозитория, топики, Marketplace

Всё ниже можно выставить одной командой через `gh` (GitHub CLI), либо руками в Settings → General и в разделе About.

## Описание репозитория (About)

```
LLM audit log, prompt-injection detection, PII redaction (ИНН, СНИЛС, ФИО) and compliance evidence for AI apps and agents: FSTEC 117, 152-ФЗ, OWASP LLM Top 10, ISO 42001, EU AI Act. Two lines to integrate, zero dependencies.
```

Website: `https://github.com/scheltsin/aiproof#readme` (пока нет домена).

## Топики (максимум 20)

```
ai-security llm-security prompt-injection audit-log compliance ai-governance pii-redaction
fstec-117 152-fz owasp-llm iso-42001 eu-ai-act nist-ai-rmf ai-bom cyclonedx
gigachat yandexgpt openai anthropic python
```

## Одной командой

```bash
gh repo edit scheltsin/aiproof \
  --description "LLM audit log, prompt-injection detection, PII redaction (ИНН, СНИЛС, ФИО) and compliance evidence for AI apps and agents: FSTEC 117, 152-ФЗ, OWASP LLM Top 10, ISO 42001, EU AI Act. Two lines to integrate, zero dependencies." \
  --homepage "https://github.com/scheltsin/aiproof#readme" \
  --add-topic ai-security --add-topic llm-security --add-topic prompt-injection --add-topic audit-log \
  --add-topic compliance --add-topic ai-governance --add-topic pii-redaction --add-topic fstec-117 \
  --add-topic 152-fz --add-topic owasp-llm --add-topic iso-42001 --add-topic eu-ai-act --add-topic nist-ai-rmf \
  --add-topic ai-bom --add-topic cyclonedx --add-topic gigachat --add-topic yandexgpt --add-topic openai \
  --add-topic anthropic --add-topic python \
  --enable-discussions --enable-issues
```

Ещё в Settings → General: Social preview (картинка 1280×640: имя, одна строка «Audit log · PII redaction · Compliance evidence for LLM apps», список стандартов), Releases включены, Packages не нужны (пакет живёт на PyPI).

## GitHub Marketplace (Action)

Требования Marketplace: `action.yml` в корне (есть), уникальное `name`, `description`, `branding` (есть), README, опубликованный релиз с тегом. Публикация: Releases → Draft a new release → галочка «Publish this Action to the GitHub Marketplace» → выбрать категории.

**Name (из action.yml):** `aiproof AI security check`

**Primary category:** Security. **Secondary:** Code quality.

**Listing description (короткое поле):**

```
AI security and compliance check for repositories that call LLMs: unsafe pickle models, LLM calls without an audit trail, prompt injections in agent files (AGENTS.md, CLAUDE.md, MCP), foreign SaaS models in regulated systems. Control maps for FSTEC 117 (Russia), OWASP LLM Top 10, ISO 42001, NIST AI RMF, EU AI Act. Produces a JSON report artifact.
```

**Пример использования (показывается на странице):**

```yaml
name: ai-security
on: [push, pull_request]
jobs:
  aiproof:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: scheltsin/aiproof@v0
        with:
          controls: ru-fstek-117,owasp-llm-2025
          fail-on: fail            # fail | manual | never
```

Тег `v0` должен указывать на последний релиз ветки 0.x: после каждого релиза `git tag -f v0 && git push -f origin v0`.

## PyPI

Workflow `release.yml` публикует пакет при пуше тега `v*` через trusted publishing. Один раз на pypi.org: Your projects → Publishing → Add a new pending publisher: owner `scheltsin`, repository `aiproof`, workflow `release.yml`, environment `pypi`. В репозитории: Settings → Environments → создать `pypi`.

Последовательность релиза: обновить версию в `pyproject.toml` и `src/aiproof/_meta.py`, `git tag -a v0.1.0 -m v0.1.0 && git push origin v0.1.0`. Дальше CI соберёт wheel, создаст GitHub Release с артефактами и опубликует на PyPI.
