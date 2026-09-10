"""Project attestation: inventory models, datasets, dependencies, LLM call
sites, agent config files and ledgers; evaluate a control set; produce an
evidence bundle (zip) that ``aiproof verify`` can check offline.

Everything is computed locally. Nothing leaves the machine.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
import zipfile
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ._meta import DEFAULT_DIR, EVIDENCE_FORMAT, NAME, VERSION, POLICY_FILE
from .config import load_policy
from .filters import scan_text
from .ledger import canonical, sha256_hex, verify_file

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox",
             ".mypy_cache", ".pytest_cache", "dist", "build", ".idea", ".vscode", "site-packages"}

MODEL_EXT = {".pt", ".pth", ".bin", ".safetensors", ".gguf", ".ggml", ".onnx", ".pkl", ".pickle", ".h5",
             ".ckpt", ".pb", ".tflite", ".joblib", ".npz", ".msgpack"}
DATASET_EXT = {".csv", ".parquet", ".jsonl", ".arrow", ".tsv"}
DATASET_DIR_HINT = re.compile(r"(^|/)(data|datasets?|train|training|corpus|eval)(/|$)", re.I)
SOURCE_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".cs", ".rb", ".php", ".rs"}
AGENT_FILES = {"AGENTS.md", "CLAUDE.md", ".cursorrules", "copilot-instructions.md", "SKILL.md", ".mcp.json",
               "mcp.json", "GEMINI.md", ".windsurfrules", "claude_desktop_config.json"}

PROVIDER_SIGNS = [
    ("openai", re.compile(r"\bfrom\s+openai\b|\bimport\s+openai\b|require\(['\"]openai['\"]\)|from\s+['\"]openai['\"]|api\.openai\.com")),
    ("anthropic", re.compile(r"\banthropic\b", re.I)),
    ("gigachat", re.compile(r"gigachat", re.I)),
    ("yandexgpt", re.compile(r"yandexgpt|llm\.api\.cloud\.yandex|foundationModels", re.I)),
    ("langchain", re.compile(r"\blangchain\b", re.I)),
    ("llama_index", re.compile(r"llama_index|llamaindex", re.I)),
    ("ollama", re.compile(r"\bollama\b|:11434", re.I)),
    ("vllm", re.compile(r"\bvllm\b", re.I)),
    ("transformers", re.compile(r"\bfrom\s+transformers\b|\bimport\s+transformers\b")),
    ("mcp", re.compile(r"\bmcp\b.*\b(server|client)\b|modelcontextprotocol", re.I)),
]
AIPROOF_SIGN = re.compile(rf"\b{NAME}\.(wrap|install|record|Guard)\b|\bfrom\s+{NAME}\b|\bimport\s+{NAME}\b")

AI_DEPS = {"torch", "tensorflow", "transformers", "openai", "anthropic", "langchain", "langchain-core",
           "llama-index", "gigachat", "yandexcloud", "sentence-transformers", "onnxruntime", "vllm",
           "safetensors", "huggingface-hub", "keras", "scikit-learn", "xgboost", "lightgbm", "mcp"}


# ------------------------------------------------------------------ helpers

def _hash_file(p: Path) -> Tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def _model_format(p: Path) -> Tuple[str, bool]:
    """Return (format, is_pickle_based)."""
    ext = p.suffix.lower()
    try:
        with open(p, "rb") as f:
            head = f.read(16)
    except Exception:
        return ext.lstrip("."), ext in {".pkl", ".pickle", ".joblib"}
    if head.startswith(b"GGUF"):
        return "gguf", False
    if head.startswith(b"\x89HDF"):
        return "hdf5", False
    if head.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(p) as z:
                names = z.namelist()
            if any(n.endswith("data.pkl") or n.endswith(".pkl") for n in names):
                return "torch-zip(pickle)", True
            return "zip", False
        except Exception:
            return "zip", ext in {".pt", ".pth", ".ckpt"}
    if ext == ".safetensors" and len(head) >= 9 and head[8:9] == b"{":
        return "safetensors", False
    if head[:1] == b"\x80" and 2 <= head[1] <= 5:
        return "pickle", True
    if ext in {".pkl", ".pickle", ".joblib"}:
        return "pickle", True
    if ext == ".onnx":
        return "onnx", False
    if ext in {".pt", ".pth", ".bin", ".ckpt"}:
        return "unknown(" + ext.lstrip(".") + ")", False
    return ext.lstrip("."), False


def _walk(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".") or d == DEFAULT_DIR]
        for fn in filenames:
            yield Path(dirpath) / fn


def _parse_requirements(text: str) -> List[Dict[str, Any]]:
    out = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = re.match(r"([A-Za-z0-9_.\-\[\]]+)\s*(==|>=|<=|~=|!=|>|<)?\s*([^;\s]*)", line)
        if not m:
            continue
        name = m.group(1).split("[")[0].lower()
        out.append({"name": name, "op": m.group(2) or "", "version": m.group(3) or "", "pinned": m.group(2) == "=="})
    return out


# ------------------------------------------------------------------ main scan

def scan_project(root: str = ".", hash_datasets: bool = True, max_dataset_mb: int = 512) -> Dict[str, Any]:
    rootp = Path(root).resolve()
    models: List[Dict[str, Any]] = []
    datasets: List[Dict[str, Any]] = []
    deps: List[Dict[str, Any]] = []
    dep_files: List[str] = []
    lock_files: List[str] = []
    llm_usage: List[Dict[str, Any]] = []
    agent_files: List[Dict[str, Any]] = []
    ledgers: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    def rel(p: Path) -> str:
        return str(p.relative_to(rootp)).replace(os.sep, "/")

    for p in _walk(rootp):
        name = p.name
        ext = p.suffix.lower()
        r = rel(p)
        try:
            if ext in MODEL_EXT:
                fmt, is_pickle = _model_format(p)
                digest, size = _hash_file(p)
                models.append({"path": r, "sha256": digest, "size": size, "format": fmt, "pickle": is_pickle})
                if is_pickle:
                    findings.append({"id": "models.pickle", "severity": "high", "path": r,
                                     "msg": f"pickle-based model format ({fmt}); convert to safetensors/onnx/gguf"})
                continue
            if ext in DATASET_EXT and DATASET_DIR_HINT.search("/" + r):
                size = p.stat().st_size
                entry: Dict[str, Any] = {"path": r, "size": size}
                if hash_datasets and size <= max_dataset_mb * 1024 * 1024:
                    entry["sha256"], _ = _hash_file(p)
                datasets.append(entry)
                continue
            if name in ("requirements.txt", "requirements-dev.txt", "requirements-prod.txt") or \
                    (name.startswith("requirements") and ext == ".txt"):
                dep_files.append(r)
                deps.extend(dict(d, file=r) for d in _parse_requirements(p.read_text("utf-8", "replace")))
                continue
            if name == "pyproject.toml":
                dep_files.append(r)
                txt = p.read_text("utf-8", "replace")
                m = re.search(r"dependencies\s*=\s*\[(.*?)\]", txt, re.S)
                if m:
                    items = re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))
                    deps.extend(dict(d, file=r) for d in _parse_requirements("\n".join(items)))
                continue
            if name == "package.json":
                dep_files.append(r)
                try:
                    pj = json.loads(p.read_text("utf-8", "replace"))
                    for sec in ("dependencies", "devDependencies"):
                        for k, v in (pj.get(sec) or {}).items():
                            deps.append({"name": k.lower(), "op": "", "version": str(v), "file": r,
                                         "pinned": bool(re.match(r"^\d", str(v)))})
                except Exception:
                    pass
                continue
            if name in ("poetry.lock", "uv.lock", "Pipfile.lock", "package-lock.json", "pnpm-lock.yaml",
                        "yarn.lock", "requirements.lock", "go.sum", "Cargo.lock"):
                lock_files.append(r)
                continue
            if name in AGENT_FILES or (ext == ".md" and name.upper() in {"AGENTS.MD", "CLAUDE.MD"}):
                txt = p.read_text("utf-8", "replace")
                fnd = scan_text(txt)
                agent_files.append({"path": r, "sha256": sha256_hex(txt.encode("utf-8")),
                                    "findings": [f.to_dict() for f in fnd]})
                for f in fnd:
                    if f.severity in ("high", "critical"):
                        findings.append({"id": "agentcfg." + f.rule, "severity": f.severity, "path": r, "msg": f.snippet})
                continue
            if ext == ".jsonl" and (DEFAULT_DIR in r or name.startswith("ledger")):
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    first = f.readline()
                if f'"fmt":"{NAME}/ledger/' in first.replace(" ", ""):
                    key = os.environ.get(f"{NAME.upper()}_KEY")
                    vr = verify_file(str(p), key.encode() if key else None)
                    has_mac = '"mac":' in first
                    ledgers.append({"path": r, **vr.to_dict(), "has_mac": has_mac})
                    if not vr.ok:
                        findings.append({"id": "ledger.broken", "severity": "critical", "path": r,
                                         "msg": "; ".join(vr.errors[:3])})
                continue
            if ext in SOURCE_EXT and p.stat().st_size < 2_000_000:
                txt = p.read_text("utf-8", "replace")
                provs = [n for n, rx in PROVIDER_SIGNS if rx.search(txt)]
                if provs:
                    covered = bool(AIPROOF_SIGN.search(txt))
                    llm_usage.append({"path": r, "providers": provs, f"{NAME}": covered})
        except Exception as e:  # never abort the scan on a single file
            findings.append({"id": "scan.error", "severity": "low", "path": r, "msg": str(e)[:200]})

    any_covered = any(u[NAME] for u in llm_usage)
    for u in llm_usage:
        if not u[NAME] and not any_covered and not any(p in ("langchain", "transformers", "mcp") for p in u["providers"]):
            findings.append({"id": "llm.uncovered", "severity": "medium", "path": u["path"],
                             "msg": f"LLM client ({', '.join(u['providers'])}) without {NAME} wrapper/install"})

    policy_path = rootp / POLICY_FILE
    policy = load_policy(str(policy_path) if policy_path.exists() else None, search_cwd=False)
    return {
        "fmt": f"{NAME}/attest/v0",
        "lib": f"{NAME}/{VERSION}",
        "root": str(rootp),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "policy": {"file": POLICY_FILE if policy_path.exists() else None, **policy.to_dict(),
                   "has_key": policy.hmac_key() is not None},
        "models": models,
        "datasets": datasets,
        "dependencies": deps,
        "dependency_files": dep_files,
        "lock_files": lock_files,
        "ai_dependencies": sorted({d["name"] for d in deps if d["name"] in AI_DEPS}),
        "llm_usage": llm_usage,
        "agent_files": agent_files,
        "ledgers": ledgers,
        "findings": findings,
    }


# ------------------------------------------------------------------ controls

CONTROLS_DIR = Path(__file__).parent / "controls"


def list_controls() -> List[Dict[str, str]]:
    """Available built-in control sets: [{id, title, version, file}]."""
    out = []
    for p in sorted(CONTROLS_DIR.glob("*.json")):
        try:
            d = json.loads(p.read_text("utf-8"))
            out.append({"id": d["id"], "title": d.get("title", ""), "version": d.get("version", ""),
                        "controls": len(d.get("controls", [])), "file": p.name})
        except Exception:
            continue
    return out


def load_controls(name: str = "ru-fstek-117") -> Dict[str, Any]:
    """Load a built-in control set by id (``ru-fstek-117``, ``owasp-llm-2025``, ...) or a JSON file path."""
    if Path(name).is_file():
        return json.loads(Path(name).read_text("utf-8"))
    for p in CONTROLS_DIR.glob("*.json"):
        try:
            d = json.loads(p.read_text("utf-8"))
        except Exception:
            continue
        if d.get("id") == name:
            return d
    fn = name.replace("-", "_").replace("ru_", "") + ".json"
    p = CONTROLS_DIR / fn
    if p.exists():
        return json.loads(p.read_text("utf-8"))
    raise FileNotFoundError(f"unknown control set: {name}; available: {', '.join(c['id'] for c in list_controls())}")


def evaluate_checks(scan: Dict[str, Any]) -> Dict[str, Tuple[str, str]]:
    """Map check id -> (status, note). status: pass | fail | manual | n/a"""
    pol = scan["policy"]
    ledgers = scan["ledgers"]
    models = scan["models"]
    deps = scan["dependencies"]
    fids = {f["id"] for f in scan["findings"]}
    n_records = sum(ld.get("records", 0) for ld in ledgers)
    c: Dict[str, Tuple[str, str]] = {}
    c["ledger.present"] = ("pass", f"{len(ledgers)} ledger(s), {n_records} records") if n_records else \
        ("fail", "no ledger records found (run the app with the wrapper or proxy)")
    c["ledger.verified"] = ("pass", "hash chain ok") if ledgers and all(ld["ok"] for ld in ledgers) else \
        ("fail", "chain broken" if ledgers else "no ledger")
    c["ledger.mac"] = ("pass", "records authenticated (HMAC)") if ledgers and all(ld.get("has_mac") for ld in ledgers) \
        else ("fail", f"no HMAC key: set {NAME.upper()}_KEY")
    if scan["llm_usage"]:
        c["ledger.covers_calls"] = ("fail", "LLM call sites without wrapper") if "llm.uncovered" in fids else \
            ("pass", f"{len(scan['llm_usage'])} call site file(s) covered")
    else:
        c["ledger.covers_calls"] = ("n/a", "no LLM client code detected")
    c["policy.filter_input"] = ("pass", "enabled") if pol.get("filter_input") else ("fail", "filter_input=false")
    c["policy.filter_output"] = ("pass", "enabled") if pol.get("filter_output") else ("fail", "filter_output=false")
    c["policy.redact"] = ("pass", ",".join(pol.get("redact_types", []))) if pol.get("redact") else ("fail", "redact=false")
    quotas = pol.get("max_requests_per_minute") or pol.get("max_tokens_per_day") or pol.get("max_prompt_chars")
    c["policy.quotas"] = ("pass", "limits set") if quotas else ("fail", "no quotas in policy")
    c["policy.app_named"] = ("pass", pol.get("app")) if pol.get("app") not in (None, "", "app") else \
        ("fail", "policy.app is the default 'app'")
    c["models.inventoried"] = ("pass", f"{len(models)} model file(s)") if models else ("n/a", "no model files in repo")
    c["models.hashed"] = ("pass", "sha256 for all") if models else ("n/a", "no model files")
    c["models.no_pickle"] = ("fail", "pickle-based models present") if "models.pickle" in fids else \
        (("pass", "no pickle formats") if models else ("n/a", "no model files"))
    ds = scan["datasets"]
    c["datasets.hashed"] = ("pass", f"{len(ds)} dataset file(s)") if ds and all("sha256" in d for d in ds) else \
        (("fail", "unhashed datasets (too large?)") if ds else ("n/a", "no dataset files"))
    c["deps.inventoried"] = ("pass", f"{len(deps)} deps") if deps else ("n/a", "no dependency manifest")
    if scan["lock_files"]:
        c["deps.pinned"] = ("pass", "lock file: " + ", ".join(scan["lock_files"][:3]))
    elif deps:
        unp = [d["name"] for d in deps if not d.get("pinned")]
        c["deps.pinned"] = ("pass", "all pinned") if not unp else ("fail", f"unpinned: {', '.join(unp[:8])}")
    else:
        c["deps.pinned"] = ("n/a", "no deps")
    c["manual"] = ("manual", "attach document")
    return c


def evaluate_controls(scan: Dict[str, Any], controls: Dict[str, Any]) -> Dict[str, Any]:
    checks = evaluate_checks(scan)
    rows = []
    summary = {"pass": 0, "fail": 0, "manual": 0, "n/a": 0}
    for ctl in controls["controls"]:
        statuses = []
        notes = []
        for ck in ctl["checks"]:
            st, note = checks.get(ck, ("n/a", "unknown check"))
            statuses.append(st)
            notes.append(f"{ck}: {note}")
        if "fail" in statuses:
            st = "fail"
        elif "manual" in statuses:
            st = "manual"
        elif all(s == "n/a" for s in statuses):
            st = "n/a"
        else:
            st = "pass"
        summary[st] += 1
        rows.append({"id": ctl["id"], "phase": ctl["phase"], "title_ru": ctl["title_ru"], "title_en": ctl["title_en"],
                     "status": st, "notes": notes, "evidence": ctl["evidence"], "xref": ctl.get("xref", {})})
    return {"controls_id": controls["id"], "controls_version": controls.get("version"), "summary": summary,
            "controls": rows, "checks": {k: {"status": v[0], "note": v[1]} for k, v in checks.items()}}


# ------------------------------------------------------------------ AI-BOM

def build_aibom(scan: Dict[str, Any]) -> Dict[str, Any]:
    comps = []
    for m in scan["models"]:
        comps.append({
            "type": "machine-learning-model",
            "name": Path(m["path"]).name,
            "version": m["sha256"][:12],
            "hashes": [{"alg": "SHA-256", "content": m["sha256"]}],
            "properties": [{"name": "path", "value": m["path"]}, {"name": "format", "value": m["format"]},
                           {"name": "size", "value": str(m["size"])}, {"name": "pickle", "value": str(m["pickle"]).lower()}],
        })
    for d in scan["datasets"]:
        comp = {"type": "data", "name": Path(d["path"]).name,
                "properties": [{"name": "path", "value": d["path"]}, {"name": "size", "value": str(d["size"])}]}
        if "sha256" in d:
            comp["hashes"] = [{"alg": "SHA-256", "content": d["sha256"]}]
        comps.append(comp)
    for dep in scan["dependencies"]:
        if dep["name"] in AI_DEPS:
            comps.append({"type": "library", "name": dep["name"], "version": dep.get("version") or "unpinned",
                          "properties": [{"name": "file", "value": dep["file"]}]})
    for u in scan["llm_usage"]:
        for prov in u["providers"]:
            comps.append({"type": "service", "name": f"llm-provider:{prov}",
                          "properties": [{"name": "path", "value": u["path"]},
                                         {"name": f"{NAME}.covered", "value": str(u[NAME]).lower()}]})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": scan["ts"], "tools": [{"name": NAME, "version": VERSION}],
                     "component": {"type": "application", "name": scan["policy"].get("app") or Path(scan["root"]).name}},
        "components": comps,
    }


# ------------------------------------------------------------------ bundle

def write_bundle(scan: Dict[str, Any], evaluation: Any, out_path: str, key: Optional[bytes] = None,
                 include_ledgers: bool = True) -> Dict[str, Any]:
    """``evaluation`` is one evaluate_controls() result or a list of them (first = primary)."""
    evaluations = evaluation if isinstance(evaluation, list) else [evaluation]
    evaluation = evaluations[0]
    aibom = build_aibom(scan)
    files: Dict[str, bytes] = {
        "attest.json": json.dumps(scan, ensure_ascii=False, indent=2).encode("utf-8"),
        "controls.json": json.dumps(evaluation, ensure_ascii=False, indent=2).encode("utf-8"),
        "aibom.json": json.dumps(aibom, ensure_ascii=False, indent=2).encode("utf-8"),
    }
    for extra in evaluations[1:]:
        files[f"controls-{extra['controls_id']}.json"] = json.dumps(extra, ensure_ascii=False, indent=2).encode("utf-8")
    if scan["policy"].get("file"):
        try:
            files["policy.json"] = (Path(scan["root"]) / scan["policy"]["file"]).read_bytes()
        except Exception:
            pass
    if include_ledgers:
        for ld in scan["ledgers"]:
            try:
                files["ledger/" + Path(ld["path"]).name] = (Path(scan["root"]) / ld["path"]).read_bytes()
            except Exception:
                pass
    manifest = {
        "fmt": EVIDENCE_FORMAT,
        "lib": f"{NAME}/{VERSION}",
        "ts": scan["ts"],
        "app": scan["policy"].get("app"),
        "controls_id": evaluation["controls_id"],
        "controls_sets": [e["controls_id"] for e in evaluations],
        "summary": evaluation["summary"],
        "summaries": {e["controls_id"]: e["summary"] for e in evaluations},
        "files": {name: {"sha256": sha256_hex(data), "size": len(data)} for name, data in files.items()},
    }
    manifest["hash"] = sha256_hex(canonical({k: v for k, v in manifest.items() if k not in ("hash", "mac")}))
    if key:
        manifest["mac"] = hmac.new(key, manifest["hash"].encode(), hashlib.sha256).hexdigest()
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
        z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    return manifest


def verify_bundle(path: str, key: Optional[bytes] = None) -> Dict[str, Any]:
    errors: List[str] = []
    with zipfile.ZipFile(path) as z:
        try:
            manifest = json.loads(z.read("manifest.json"))
        except Exception as e:
            return {"ok": False, "errors": [f"manifest.json missing/invalid: {e}"]}
        body = {k: v for k, v in manifest.items() if k not in ("hash", "mac")}
        if sha256_hex(canonical(body)) != manifest.get("hash"):
            errors.append("manifest hash mismatch")
        if key is not None:
            expected = hmac.new(key, str(manifest.get("hash")).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, manifest.get("mac", "")):
                errors.append("manifest mac mismatch (wrong key or forged bundle)")
        for name, meta in manifest.get("files", {}).items():
            try:
                data = z.read(name)
            except KeyError:
                errors.append(f"missing file: {name}")
                continue
            if sha256_hex(data) != meta.get("sha256"):
                errors.append(f"modified file: {name}")
            if name.startswith("ledger/"):
                tmp = Path(path).with_suffix(f".{zlib.crc32(name.encode()):08x}.tmp")
                tmp.write_bytes(data)
                try:
                    vr = verify_file(str(tmp), key)
                    if not vr.ok:
                        errors.extend(f"{name}: {e}" for e in vr.errors[:5])
                finally:
                    tmp.unlink(missing_ok=True)
    return {"ok": not errors, "errors": errors, "manifest": manifest}
