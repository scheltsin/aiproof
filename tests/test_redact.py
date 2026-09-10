from aiproof.redact import redact, redact_obj, valid_inn, valid_snils, valid_ogrn, valid_luhn


def test_inn_checksums():
    assert valid_inn("7707083893")      # Сбербанк, 10 digits
    assert valid_inn("500100732259")    # 12 digits
    assert not valid_inn("7707083894")
    assert not valid_inn("1234567890")
    assert not valid_inn("123")


def test_snils_checksum():
    assert valid_snils("112-233-445 95")
    assert not valid_snils("112-233-445 96")


def test_ogrn_checksum():
    assert valid_ogrn("1027700132195")      # ОГРН Сбербанка
    assert not valid_ogrn("1027700132196")
    assert valid_ogrn("304500116000157")    # ОГРНИП example
    assert not valid_ogrn("304500116000158")


def test_luhn():
    assert valid_luhn("4111 1111 1111 1111")
    assert not valid_luhn("4111 1111 1111 1112")


def test_redact_mixed_text():
    t = ("ИНН 7707083893, СНИЛС 112-233-445 95, тел +7 (916) 123-45-67, карта 4111 1111 1111 1111, "
         "mail a@b.ru, паспорт 45 12 345678, счёт 40702810900000012345, ОГРН 1027700132195, "
         "key sk-abcdefghijklmnopqrstuvwxyz1234")
    out, findings = redact(t)
    kinds = sorted(f.type for f in findings)
    assert kinds == sorted(["inn", "snils", "phone_ru", "card", "email", "passport_rf", "bank_account", "ogrn", "secret"])
    for raw in ("7707083893", "112-233-445 95", "916", "4111", "a@b.ru", "345678", "40702810900000012345", "sk-abc"):
        assert raw not in out


def test_no_false_positive_on_plain_numbers():
    out, findings = redact("Заказ 1234567890 на сумму 100000 руб, дата 2026-09-10, счётчик 0000000000")
    assert findings == []
    assert "1234567890" in out


def test_stable_tokens():
    a, _ = redact("ИНН 7707083893")
    b, _ = redact("ещё раз 7707083893")
    tok = a.split("ИНН ")[1]
    assert tok in b


def test_redact_obj_nested():
    data = {"messages": [{"role": "user", "content": "мой email x@y.ru"}], "n": 1}
    out, findings = redact_obj(data)
    assert out["n"] == 1
    assert "x@y.ru" not in out["messages"][0]["content"]
    assert findings[0].type == "email"


def test_types_filter():
    out, findings = redact("email x@y.ru ИНН 7707083893", types=["inn"])
    assert "x@y.ru" in out and "7707083893" not in out
