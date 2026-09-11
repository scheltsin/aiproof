from aiproof.redact import redact, redact_obj, valid_inn, valid_luhn, valid_ogrn, valid_snils


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


def test_extended_ru_detectors():
    t = ("Клиент: Иванов Иван Иванович, дата рождения 12.05.1985, паспорт 45 12 345678, загранпаспорт 65 1234567, "
         "в/у 77 АВ 123456, полис ОМС 1234567890123452, адрес: г. Москва, ул. Ленина, д. 5, корп. 2, кв. 12. "
         "КПП 770701001 ОКПО 00032537 БИК 044525225, IBAN GB82 WEST 1234 5698 7654 32, авто А123ВС777, "
         "VIN XTA210930Y2696785, кадастровый 77:01:0001001:1234, ip 192.168.1.10, CVV 123, менеджер Петров П.С.")
    out, findings = redact(t)
    kinds = {f.type for f in findings}
    expected = {"fio", "birth_date", "passport_rf", "intl_passport", "driver_license", "oms", "address", "kpp",
                "okpo", "bik", "iban", "vehicle_plate", "vin", "cadastral", "ipv4", "cvv"}
    assert expected <= kinds, expected - kinds
    for raw in ("Иванов Иван", "12.05.1985", "345678", "1234567", "Ленина", "770701001", "00032537", "044525225",
                "WEST", "А123ВС", "XTA210930", "0001001", "192.168", "Петров П"):
        assert raw not in out, raw


def test_extended_no_false_positives():
    samples = [
        "Заказ 1234567890 на сумму 100000 руб, дата 2026-09-10",
        "Привет, Иван Иванович! Сегодня 12.05.2026 встреча в 10:00.",
        "Версия 192.168.0.256 не адрес, а v1.2.3 версия",
        "Московская область, Ленинский проспект",
        "заказ 12345678 отгружен, накладная 87654321",
    ]
    for s in samples:
        out, f = redact(s)
        assert f == [], (s, [x.type for x in f])


def test_okpo_and_iban_checksums():
    from aiproof.redact import valid_iban, valid_okpo
    assert valid_okpo("00032537") and not valid_okpo("00032538")
    assert valid_iban("GB82 WEST 1234 5698 7654 32") and not valid_iban("GB82 WEST 1234 5698 7654 33")
