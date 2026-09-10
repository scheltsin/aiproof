#!/usr/bin/env python3
"""Rename the project everywhere:  python scripts/rename.py newname

Renames the package directory, identifiers, env-var prefix, file names and
docs. Run from the repository root on a clean git tree, then review the diff.
"""
import re
import sys
from pathlib import Path

OLD = "aiproof"


def main() -> int:
    if len(sys.argv) != 2 or not re.fullmatch(r"[a-z][a-z0-9_]{1,30}", sys.argv[1]):
        print("usage: rename.py <newname>   (lowercase, letters/digits/_)")
        return 2
    new = sys.argv[1]
    root = Path(__file__).resolve().parents[1]
    pkg_old = root / "src" / OLD
    pkg_new = root / "src" / new
    if pkg_old.exists():
        pkg_old.rename(pkg_new)
    skill_old = root / "skills" / OLD
    if skill_old.exists():
        skill_old.rename(root / "skills" / new)
    ex_old = root / "examples" / f"{OLD}.json"
    if ex_old.exists():
        ex_old.rename(root / "examples" / f"{new}.json")
    n = 0
    for p in root.rglob("*"):
        if p.is_dir() or ".git" in p.parts or p.suffix in {".pyc", ".zip", ".png"}:
            continue
        if p.name == "rename.py":
            continue
        try:
            txt = p.read_text("utf-8")
        except Exception:
            continue
        new_txt = txt.replace(OLD.upper(), new.upper()).replace(OLD.capitalize(), new.capitalize()).replace(OLD, new)
        if new_txt != txt:
            p.write_text(new_txt, "utf-8")
            n += 1
    (root / "scripts" / "rename.py").write_text(
        (root / "scripts" / "rename.py").read_text("utf-8").replace(f'OLD = "{OLD}"', f'OLD = "{new}"'), "utf-8")
    print(f"renamed {OLD} -> {new} in {n} files; now: pip install -e . && pytest -q")
    return 0


if __name__ == "__main__":
    sys.exit(main())
