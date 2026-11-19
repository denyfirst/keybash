"""Tests scripts/rust-advisories.py. Run from the repository root."""
import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path

spec = importlib.util.spec_from_file_location("advisories", Path(__file__).with_name("rust-advisories.py"))
advisories = importlib.util.module_from_spec(spec)
spec.loader.exec_module(advisories)

# Package IDs as cargo writes them, registry and path, with and without a name.
ids = {
    "registry+https://github.com/rust-lang/crates.io-index#rsa@0.10.0-rc.18": ("rsa", "0.10.0-rc.18"),
    "path+file:///build/ironrdp/crates/ironrdp-web#0.0.0": ("ironrdp-web", "0.0.0"),
    "path+file:///build/ironrdp/crates/iron-remote-desktop#iron-remote-desktop@0.8.1": ("iron-remote-desktop", "0.8.1"),
}
for package_id, want in ids.items():
    assert advisories.package_name_version(package_id) == want, package_id
for bad in ["rsa@1.0", "#1.0", "x#", "src#c d@1", ""]:
    try:
        advisories.package_name_version(bad)
    except ValueError:
        continue
    raise SystemExit(f"package id {bad!r} accepted")

messages = [
    "Compiling noise that is not JSON",
    json.dumps({"reason": "compiler-artifact", "package_id": "registry+https://github.com/rust-lang/crates.io-index#rsa@0.10.0-rc.18"}),
    json.dumps({"reason": "build-script-executed", "package_id": "registry+https://github.com/rust-lang/crates.io-index#zstd-sys@2.1.2"}),
    json.dumps({"reason": "compiler-artifact", "package_id": "path+file:///build/ironrdp/crates/ironrdp-web#0.0.0"}),
]
assert advisories.built(messages) == [("ironrdp-web", "0.0.0"), ("rsa", "0.10.0-rc.18")]
try:
    advisories.built(["{}"])
    raise SystemExit("a build without compiled crates accepted")
except SystemExit as stop:
    assert "no compiled crate" in str(stop)


def entry(id, name, version):
    return {"advisory": {"id": id, "title": "t"}, "package": {"name": name, "version": version}}


def audit(vulnerabilities=(), **warnings):
    return {"vulnerabilities": {"list": list(vulnerabilities)}, "warnings": {k: list(v) for k, v in warnings.items()}}


compiled = [("rsa", "0.10.0-rc.18"), ("paste", "1.0.15"), ("chrono", "0.4.45"), ("heapless", "0.7.17")]
cases = {
    "a vulnerability on a crate never built": (audit([entry("RUSTSEC-2026-0512", "hickory-proto", "0.25.2")]), 0),
    "the reviewed rsa advisory": (audit([entry("RUSTSEC-2023-0071", "rsa", "0.10.0-rc.18")]), 0),
    "the reviewed chrono advisory": (audit(unmaintained=[entry("RUSTSEC-2026-0543", "chrono", "0.4.45")]), 0),
    "a new chrono advisory": (audit([entry("RUSTSEC-2027-0003", "chrono", "0.4.45")]), 1),
    "the chrono review on another crate": (audit(unmaintained=[entry("RUSTSEC-2026-0543", "paste", "1.0.15")]), 1),
    "the reviewed heapless advisories": (audit(unsound=[entry(f"RUSTSEC-2026-{n:04d}", "heapless", "0.7.17") for n in range(574, 583)]), 0),
    "a new heapless advisory": (audit(unsound=[entry("RUSTSEC-2027-0004", "heapless", "0.7.17")]), 1),
    "a heapless review on another crate": (audit(unsound=[entry("RUSTSEC-2026-0574", "paste", "1.0.15")]), 1),
    "a new rsa advisory": (audit([entry("RUSTSEC-2027-0001", "rsa", "0.10.0-rc.18")]), 1),
    "the reviewed ID on another crate": (audit([entry("RUSTSEC-2023-0071", "paste", "1.0.15")]), 1),
    "an unmaintained compiled crate": (audit(unmaintained=[entry("RUSTSEC-2024-0436", "paste", "1.0.15")]), 1),
    "an unsound compiled crate": (audit(unsound=[entry("RUSTSEC-2026-0400", "paste", "1.0.15")]), 1),
    "the same crate at another version": (audit([entry("RUSTSEC-2027-0002", "rsa", "0.9.8")]), 0),
}
for name, (report, want) in cases.items():
    with redirect_stdout(io.StringIO()):
        got = advisories.check(compiled, report)
    assert got == want, f"{name}: {got}, want {want}"
for broken in [{}, {"vulnerabilities": {}}, {"vulnerabilities": {"list": "x"}}, {"vulnerabilities": {"list": []}, "warnings": {"unsound": "x"}},
               {"vulnerabilities": {"list": [{"advisory": {"id": "X"}}]}}]:
    try:
        with redirect_stdout(io.StringIO()):
            advisories.check(compiled, broken)
    except (KeyError, ValueError, TypeError):
        continue
    raise SystemExit(f"broken report {broken!r} accepted")
print(f"advisories: {len(ids)} ids, {len(cases)} reports and 5 broken ones as expected")
