import json

from aiproof.ledger import Ledger, verify_file, GENESIS


def test_chain_and_verify(tmp_path):
    p = tmp_path / "l.jsonl"
    led = Ledger(str(p), key=b"k", app="t")
    r1 = led.append("e", {"a": 1})
    r2 = led.append("e", {"a": 2})
    assert r1["prev"] == GENESIS and r2["prev"] == r1["hash"]
    assert "mac" in r1
    res = verify_file(str(p), b"k")
    assert res.ok and res.records == 2 and res.last_hash == r2["hash"]


def test_continues_after_restart(tmp_path):
    p = tmp_path / "l.jsonl"
    Ledger(str(p), app="t").append("e", {"a": 1})
    led2 = Ledger(str(p), app="t")
    r = led2.append("e", {"a": 2})
    assert r["seq"] == 2
    assert verify_file(str(p)).ok


def test_detects_modification(tmp_path):
    p = tmp_path / "l.jsonl"
    led = Ledger(str(p), app="t")
    led.append("e", {"content": "hello"})
    led.append("e", {"content": "world"})
    lines = p.read_text("utf-8").splitlines()
    lines[0] = lines[0].replace("hello", "hullo")
    p.write_text("\n".join(lines) + "\n", "utf-8")
    res = verify_file(str(p))
    assert not res.ok
    assert any("modified" in e for e in res.errors)


def test_detects_deletion_and_reorder(tmp_path):
    p = tmp_path / "l.jsonl"
    led = Ledger(str(p), app="t")
    for i in range(3):
        led.append("e", {"i": i})
    lines = p.read_text("utf-8").splitlines()
    p.write_text("\n".join([lines[0], lines[2]]) + "\n", "utf-8")
    assert not verify_file(str(p)).ok
    p.write_text("\n".join([lines[1], lines[0], lines[2]]) + "\n", "utf-8")
    assert not verify_file(str(p)).ok


def test_detects_truncation_with_head(tmp_path):
    p = tmp_path / "l.jsonl"
    led = Ledger(str(p), app="t")
    led.append("e", {"i": 0})
    head = led.append("e", {"i": 1})["hash"]
    lines = p.read_text("utf-8").splitlines()
    p.write_text(lines[0] + "\n", "utf-8")
    assert verify_file(str(p)).ok  # chain itself is fine
    assert not verify_file(str(p), expected_head=head).ok


def test_forged_chain_without_key_fails_mac(tmp_path):
    p = tmp_path / "l.jsonl"
    Ledger(str(p), key=b"real", app="t").append("e", {"i": 0})
    # attacker rewrites the file with a valid chain but no key
    p.unlink()
    Ledger(str(p), key=None, app="t").append("e", {"i": 999})
    res = verify_file(str(p), b"real")
    assert not res.ok and any("mac" in e for e in res.errors)
    rec = json.loads(p.read_text().splitlines()[0])
    assert rec["i"] == 999
