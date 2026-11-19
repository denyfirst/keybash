"""Tests for vendor-ironrdp-web.py: what it vendors, and what --check refuses."""
from pathlib import Path
import hashlib
import importlib.util
import io
import json
import shutil
import tempfile
from contextlib import redirect_stdout

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("vendor", here / "vendor-ironrdp-web.py")
vendor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vendor)


def fake_repo(root, commit="a" * 40):
    (root / "scripts").mkdir(parents=True)
    (root / "ironrdp").mkdir()
    (root / "scripts/build-ironrdp-web.sh").write_text(f"#!/bin/sh\nrust=1.94.1\nbindgen=0.2.129\ncommit={commit}\n")
    (root / "ironrdp/graphics-pipeline.diff").write_bytes(b"patch\n")


def fake_build(out, files=None):
    out.mkdir(parents=True)
    files = files or {name: f"{name} bytes\n".encode() for name in vendor.FILES}
    lines = []
    for name, data in files.items():
        (out / name).write_bytes(data)
        lines.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def refused(action):
    try:
        with redirect_stdout(io.StringIO()):
            action()
    except (SystemExit, OSError):
        return True
    return False


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    repo, out, target = tmp / "repo", tmp / "out", tmp / "vendor"
    fake_repo(repo)
    fake_build(out)

    # Vendoring writes the files and a manifest of the pin; --check then passes.
    manifest = vendor.vendor(out, target, False, repo)
    assert manifest["commit"] == "a" * 40 and manifest["rust"] == "1.94.1"
    assert manifest["wasm_bindgen"] == "0.2.129"
    assert manifest["patch_sha256"] == hashlib.sha256(b"patch\n").hexdigest()
    assert sorted(p.name for p in target.iterdir()) == sorted(vendor.FILES + ["manifest.json"])
    assert json.loads((target / "manifest.json").read_text()) == manifest
    vendor.vendor(out, target, True, repo)

    # A vendored byte changed, a file added or removed: refused.
    for change in ["byte", "extra", "missing"]:
        copy = tmp / f"vendor-{change}"
        shutil.copytree(target, copy)
        if change == "byte":
            data = bytearray((copy / "ironrdp_web_bg.wasm").read_bytes())
            data[0] ^= 1
            (copy / "ironrdp_web_bg.wasm").write_bytes(bytes(data))
        elif change == "extra":
            (copy / "other.js").write_bytes(b"x")
        else:
            (copy / "ironrdp_web.js").unlink()
        assert refused(lambda: vendor.vendor(out, copy, True, repo)), change

    # Another pin or another patch: the manifest no longer matches.
    for edit in ["commit", "patch"]:
        other = tmp / f"repo-{edit}"
        fake_repo(other, commit="b" * 40 if edit == "commit" else "a" * 40)
        if edit == "patch":
            (other / "ironrdp/graphics-pipeline.diff").write_bytes(b"other patch\n")
        assert refused(lambda: vendor.vendor(out, target, True, other)), edit

    # A build whose files do not match its own sums, or one too large: refused.
    bad = tmp / "out-bad"
    fake_build(bad)
    (bad / "ironrdp_web.js").write_bytes(b"changed after the build\n")
    assert refused(lambda: vendor.vendor(bad, tmp / "v-bad", False, repo))
    big = tmp / "out-big"
    files = {name: b"x" for name in vendor.FILES}
    files["ironrdp_web_bg.wasm"] = b"\0" * (16 * 1024 * 1024 + 1)
    fake_build(big, files)
    assert refused(lambda: vendor.vendor(big, tmp / "v-big", False, repo))

    # A build script that pins no full commit: refused.
    loose = tmp / "repo-loose"
    fake_repo(loose, commit="master")
    assert refused(lambda: vendor.vendor(out, tmp / "v-loose", False, loose))

print("vendor-ironrdp-web: vendoring, the pin and every refusal as expected")
