"""Tests the licence expression rule of scripts/rust-licences.py.

Run from the repository root: python3 scripts/rust-licences-test.py
"""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("licences", Path(__file__).with_name("rust-licences.py"))
licences = importlib.util.module_from_spec(spec)
spec.loader.exec_module(licences)

CASES = {
    "MIT": True,
    "MIT OR Apache-2.0": True,
    "MIT/Apache-2.0": True,
    "(MIT OR Apache-2.0) AND Unicode-3.0": True,
    "Apache-2.0 WITH LLVM-exception": True,
    "Apache-2.0 OR LGPL-2.1-or-later OR MIT": True,
    "MIT AND (GPL-3.0 OR Zlib)": True,
    "GPL-2.0 WITH LLVM-exception OR MIT": True,
    "GPL-3.0": False,
    "SSPL-1.0": False,
    "MIT AND GPL-2.0": False,
    "Apache-2.0 WITH Other-exception": False,
    "(GPL-3.0 OR SSPL-1.0) AND MIT": False,
}
MALFORMED = ["", " ", "MIT OR", "(MIT", "MIT)", "AND MIT", "MIT WITH", "MIT;rm", "MIT OR OR Zlib", "()"]

for expression, want in CASES.items():
    got = licences.allowed(expression)
    assert got is want, f"{expression!r}: {got}, want {want}"
for expression in MALFORMED:
    try:
        licences.allowed(expression)
    except ValueError:
        continue
    raise SystemExit(f"malformed {expression!r} accepted")
print(f"licence rule: {len(CASES)} expressions and {len(MALFORMED)} malformed ones as expected")
