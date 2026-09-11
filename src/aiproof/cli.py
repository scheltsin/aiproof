"""Command line: init | verify | attest | check | proxy | redact | policy | version"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from ._meta import DEFAULT_DIR, ENV_PREFIX, NAME, POLICY_FILE, VERSION


def _key() -> Optional[bytes]:
    k = os.environ.get(f"{ENV_PREFIX}_KEY")
    return k.encode() if k else None


def _c(s: str, code: str) -> str:
    if not sys.stdout.isatty():
        return s
    return {"g": "\033[32m", "r": "\033[31m", "y": "\033[33m", "b": "\033[1m", "d": "\033[2m"}[code] + s + "\033[0m"


def cmd_init(a: argparse.Namespace) -> int:
    from .config import write_policy_file
    if Path(POLICY_FILE).exists() and not a.force:
        print(f"{POLICY_FILE} already exists (use --force to overwrite)")
        return 0
    write_policy_file(POLICY_FILE, preset=a.preset, app=a.app or Path.cwd().name)
    Path(DEFAULT_DIR).mkdir(exist_ok=True)
    gi = Path(".gitignore")
    line = f"{DEFAULT_DIR}/\n"
    if not gi.exists() or line.strip() not in gi.read_text("utf-8", "replace").splitlines():
        with open(gi, "a", encoding="utf-8") as f:
            f.write(("\n" if gi.exists() else "") + f"# {NAME} local ledgers (ship them to your SIEM instead)\n" + line)
    print(f"created {POLICY_FILE} (preset={a.preset}, app={a.app or Path.cwd().name})")
    print(f"next:  import {NAME}; client = {NAME}.wrap(OpenAI())   # or {NAME}.install()")
    print(f"       export {ENV_PREFIX}_KEY=$(openssl rand -hex 32)   # authenticate the ledger (recommended)")
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    from .attest import verify_bundle
    from .ledger import verify_chain, verify_file
    key = _key()
    rc = 0
    paths: List[str] = a.paths or [os.path.join(DEFAULT_DIR, "ledger.jsonl")]
    for p in paths:
        if os.path.isdir(p):
            r = verify_chain(p, key)
            status = _c("OK ", "g") if r.ok else _c("FAIL", "r")
            print(f"{status} chain {p}: {r.records} records across segments, head {r.last_hash[:16]}…")
            for e in r.errors:
                print("   " + _c(e, "r"))
            rc |= 0 if r.ok else 1
            continue
        if p.endswith(".zip"):
            res = verify_bundle(p, key)
            s = res.get("manifest", {}).get("summary")
            print(f"{_c('OK ', 'g') if res['ok'] else _c('FAIL', 'r')} bundle {p}  {s or ''}")
            for e in res["errors"]:
                print("   " + _c(e, "r"))
            rc |= 0 if res["ok"] else 1
            continue
        r = verify_file(p, key, expected_head=a.head)
        status = _c("OK ", "g") if r.ok else _c("FAIL", "r")
        mac = "mac verified" if r.mac_checked else f"mac not checked (set {ENV_PREFIX}_KEY)"
        seg = f", continues chain from {r.chained_from[:16]}…" if r.chained_from else ""
        print(f"{status} {p}: {r.records} records, head {r.last_hash[:16]}…, {mac}{seg}")
        for e in r.errors:
            print("   " + _c(e, "r"))
        rc |= 0 if r.ok else 1
    if a.json:
        print(json.dumps(r.to_dict(), ensure_ascii=False))
    return rc


def _print_controls(ev: Dict[str, Any]) -> None:
    sym = {"pass": _c("PASS ", "g"), "fail": _c("FAIL ", "r"), "manual": _c("MANUAL", "y"), "n/a": _c("N/A  ", "d")}
    print(_c(f"\nControls: {ev['controls_id']} ({ev.get('controls_version')})", "b"))
    for row in ev["controls"]:
        print(f"  {sym[row['status']]} {row['id']:<10} {row['title_ru']}")
        if row["status"] in ("fail", "manual"):
            for n in row["notes"]:
                if ("fail" in n) or ("no " in n) or ("manual" in n) or ("attach" in n) or ("unpinned" in n) or ("not" in n):
                    print(f"           {_c(n, 'd')}")
    s = ev["summary"]
    print(f"\n  pass {s['pass']}  fail {s['fail']}  manual {s['manual']}  n/a {s['n/a']}")


def cmd_controls(a: argparse.Namespace) -> int:
    from .attest import list_controls
    for c in list_controls():
        print(f"  {c['id']:<16} {c['controls']:>3} controls  v{c['version']:<10} {c['title']}")
    print(f"\nuse: {NAME} attest --controls ru-fstek-117,owasp-llm-2025   (or a path to your own json)")
    return 0


def cmd_attest(a: argparse.Namespace, check_only: bool = False) -> int:
    from .attest import evaluate_controls, load_controls, scan_project, write_bundle
    scan = scan_project(a.path, hash_datasets=not a.no_hash_datasets)
    try:
        sets = [load_controls(n.strip()) for n in a.controls.split(",") if n.strip()]
    except FileNotFoundError as e:
        print(_c(str(e), "r"))
        return 2
    evs = [evaluate_controls(scan, c) for c in sets]
    ev = evs[0]

    print(_c(f"{NAME} {'check' if check_only else 'attest'} v{VERSION}  root={scan['root']}", "b"))
    print(f"  models {len(scan['models'])}  datasets {len(scan['datasets'])}  deps {len(scan['dependencies'])}"
          f" (ai: {', '.join(scan['ai_dependencies']) or '-'})  llm call sites {len(scan['llm_usage'])}"
          f"  agent files {len(scan['agent_files'])}  ledgers {len(scan['ledgers'])}")
    if scan["findings"]:
        print(_c("\nFindings:", "b"))
        for f in sorted(scan["findings"], key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}[x["severity"]]):
            col = "r" if f["severity"] in ("critical", "high") else "y"
            print(f"  {_c(f['severity'].upper(), col):<18} {f['id']:<22} {f['path']}: {f['msg']}")
    for e in evs:
        _print_controls(e)

    if not check_only:
        out = a.out or os.path.join(DEFAULT_DIR, f"evidence-{scan['ts'][:10]}.zip")
        manifest = write_bundle(scan, evs, out, key=_key(), include_ledgers=not a.no_ledgers)
        print(f"\nevidence bundle: {out}  (manifest hash {manifest['hash'][:16]}…, "
              f"{'signed' if 'mac' in manifest else 'unsigned: set ' + ENV_PREFIX + '_KEY'})")
        print(f"verify with:     {NAME} verify {out}")
    if a.json:
        Path(a.json).write_text(json.dumps({"scan": scan, "controls": ev, "control_sets": evs},
                                           ensure_ascii=False, indent=2), "utf-8")
        print(f"json report:     {a.json}")

    fail_on = a.fail_on
    bad = any(e["summary"]["fail"] > 0 or (fail_on == "manual" and e["summary"]["manual"] > 0) for e in evs)
    sev_bad = any(f["severity"] in ("critical", "high") for f in scan["findings"])
    if check_only:
        return 1 if (bad or sev_bad) and fail_on != "never" else 0
    return 0


def cmd_check(a: argparse.Namespace) -> int:
    return cmd_attest(a, check_only=True)


def cmd_proxy(a: argparse.Namespace) -> int:
    from .proxy import serve
    serve(a.upstream, a.listen, policy=a.policy)
    return 0


def cmd_redact(a: argparse.Namespace) -> int:
    from .redact import DETECTORS, redact
    if a.types:
        for d in DETECTORS:
            print(f"  {d.name:<16} {'checksum' if d.validator else 'pattern/context'}")
        return 0
    text = sys.stdin.read() if not a.text else " ".join(a.text)
    out, findings = redact(text)
    sys.stdout.write(out if out.endswith("\n") else out + "\n")
    if findings:
        kinds: Dict[str, int] = {}
        for f in findings:
            kinds[f.type] = kinds.get(f.type, 0) + 1
        print(_c("redacted: " + ", ".join(f"{k}={v}" for k, v in kinds.items()), "d"), file=sys.stderr)
    return 0


def cmd_policy(a: argparse.Namespace) -> int:
    from .config import load_policy
    p = load_policy(a.preset)
    print(json.dumps(p.to_dict(), ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog=NAME, description=f"{NAME} v{VERSION}: audit trail, PII redaction and "
                                 "compliance evidence for LLM apps and agents")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help=f"create {POLICY_FILE} and {DEFAULT_DIR}/")
    s.add_argument("--preset", default="ru-fstek-117", choices=["default", "ru-fstek-117", "strict"])
    s.add_argument("--app", default=None, help="application / system id")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("verify", help="verify ledger files, a ledger directory (all rotated segments) or evidence bundles (.zip)")
    s.add_argument("paths", nargs="*")
    s.add_argument("--head", default=None, help="expected last hash (detect truncation)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_verify)

    for name, fn, help_ in (("attest", cmd_attest, "scan project, evaluate controls, write evidence bundle"),
                            ("check", cmd_check, "CI mode: scan + evaluate, exit 1 on failures")):
        s = sub.add_parser(name, help=help_)
        s.add_argument("path", nargs="?", default=".")
        s.add_argument("--controls", default="ru-fstek-117",
                       help="comma-separated control set ids or json paths (see `%s controls`)" % NAME)
        s.add_argument("--out", default=None, help="evidence bundle path (.zip)")
        s.add_argument("--json", default=None, help="write full json report to this file")
        s.add_argument("--fail-on", default="fail", choices=["fail", "manual", "never"])
        s.add_argument("--no-ledgers", action="store_true", help="do not include ledgers in the bundle")
        s.add_argument("--no-hash-datasets", action="store_true")
        s.set_defaults(fn=fn)

    s = sub.add_parser("controls", help="list built-in control sets (FSTEC 117, OWASP LLM, EU AI Act, ISO 42001, ...)")
    s.set_defaults(fn=cmd_controls)

    s = sub.add_parser("proxy", help="local reverse proxy for OpenAI-compatible APIs (zero code changes)")
    s.add_argument("--upstream", required=True, help="e.g. https://api.openai.com or https://gigachat.devices.sberbank.ru/api")
    s.add_argument("--listen", default="127.0.0.1:8787")
    s.add_argument("--policy", default=None)
    s.set_defaults(fn=cmd_proxy)

    s = sub.add_parser("redact", help="redact PII/secrets from stdin or arguments")
    s.add_argument("text", nargs="*")
    s.add_argument("--types", action="store_true", help="list detector types")
    s.set_defaults(fn=cmd_redact)

    s = sub.add_parser("policy", help="print the effective policy")
    s.add_argument("preset", nargs="?", default=None)
    s.set_defaults(fn=cmd_policy)

    s = sub.add_parser("version")
    s.set_defaults(fn=lambda a: print(f"{NAME} {VERSION}") or 0)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    a = ap.parse_args(argv)
    try:
        return int(a.fn(a) or 0)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
