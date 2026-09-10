# PII / secret detectors (`aiproof redact --types`)

25 built-in detectors. "checksum" = the value must pass the identifier's own check digit algorithm (low false positives); "context" = the value is taken only next to a keyword (паспорт, полис, КПП…); "pattern" = the shape alone is specific enough.

| type | what | method |
|---|---|---|
| `secret` | private keys, OpenAI/Anthropic/AWS/GitHub/GitLab/Slack/Google tokens, JWT, `password=…` | pattern |
| `fio` | ФИО: `Иванов Иван Иванович`, `Иван Иванович Иванов`, `Иванов И.И.`, `И.И. Иванов` | pattern (patronymic endings / initials) |
| `address` | `г. Москва, ул. Ленина, д. 5, корп. 2, кв. 12` (street + house required) | pattern |
| `birth_date` | date next to «дата рождения / д.р. / родился / DOB» | context + date validity |
| `passport_rf` | паспорт РФ `45 12 345678` | context |
| `intl_passport` | загранпаспорт `65 1234567` | context |
| `driver_license` | водительское удостоверение `77 АВ 123456` | context |
| `birth_cert` | свидетельство о рождении `IV-АБ №123456` | context |
| `oms` | полис ОМС, 16 digits | context + Luhn |
| `kpp` | КПП `770701001` | context |
| `cvv` | CVV/CVC next to keyword | context |
| `snils` | СНИЛС `112-233-445 95` | checksum |
| `bank_account` | расчётный / корреспондентский счёт, 20 digits (40x/42x/45x/47x/30x/20x) | pattern |
| `ogrn` | ОГРН (13) / ОГРНИП (15) | checksum |
| `inn` | ИНН (10 / 12) | checksum |
| `okpo` | ОКПО (8 / 10) | context + checksum |
| `bik` | БИК `04xxxxxxx` | pattern |
| `card` | bank cards 13–19 digits | Luhn |
| `iban` | IBAN | mod-97 checksum |
| `cadastral` | кадастровый номер `77:01:0001001:1234` | pattern |
| `vehicle_plate` | госномер `А123ВС777` | pattern |
| `vin` | VIN, 17 chars | pattern |
| `phone_ru` | `+7 (916) 123-45-67`, `8 495 …` | pattern + prefix rule |
| `email` | e-mail | pattern |
| `ipv4` | IPv4 (except 0.0.0.0 / 127.0.0.1) | pattern + range |

Trivial values (`0000000000`) never match even if the checksum passes. Each match is replaced with a stable token `<TYPE:xxxx>` (SHA-256 of salt + value, first 4 hex), so the same value gives the same token within a process without storing it; set `AIPROOF_REDACT_SALT` to make tokens stable across processes.

Restrict with policy `redact_types` (`["inn","snils","fio"]`), extend at runtime:

```python
aiproof.register_detector("contract_no", r"\bДОГ-\d{6}\b")
aiproof.register_detector("employee_id", r"(?i:табельный\s*№?\s*)(\d{6})", group=1)
```

Known gaps (contributions welcome): name + patronymic without surname («Иван Иванович»), Latin-script names, free-form addresses without «ул./д.», postal codes without context, ОКТМО/ОКАТО, номера трудовых книжек, ДМС polices (formats vary by insurer), 2-факторные коды.
