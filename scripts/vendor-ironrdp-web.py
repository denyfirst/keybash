"""Vendor IronRDP's browser client, as scripts/build-ironrdp-web.sh built it.

    vendor-ironrdp-web.py OUT            copy OUT into web/vendor/ironrdp
    vendor-ironrdp-web.py --check OUT    fail unless what is vendored is OUT

OUT is the build script's output directory. Its SHA256SUMS must match the
files, and the manifest records the pin they came from: IronRDP's commit,
Keybash's patch, Rust and wasm-bindgen. CI runs --check on a fresh build, so
a vendored module can only change through the pinned source and the patch.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re

FILES = [
    "ironrdp_web.js",
    "ironrdp_web_bg.wasm",
    "IRONRDP-LICENSE-MIT",
    "IRONRDP-LICENSE-APACHE",
    "CRATES.txt",
]
MOST = {"ironrdp_web_bg.wasm": 16 * 1024 * 1024}
DEFAULT_MOST = 1024 * 1024
REPO = Path(__file__).resolve().parents[1]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def pin(repo):
    """The pin scripts/build-ironrdp-web.sh builds from."""
    script = (repo / "scripts/build-ironrdp-web.sh").read_text()
    values = {}
    for key in ["commit", "rust", "bindgen"]:
        found = re.findall(r"^" + key + r"=([0-9a-f.]+)$", script, re.MULTILINE)
        if len(found) != 1:
            raise SystemExit(f"build-ironrdp-web.sh does not name one {key}")
        values[key] = found[0]
    if not re.fullmatch(r"[0-9a-f]{40}", values["commit"]):
        raise SystemExit("build-ironrdp-web.sh does not pin a full commit")
    patch = (repo / "ironrdp/graphics-pipeline.diff").read_bytes()
    return {
        "project": "IronRDP browser client (ironrdp-web), with Keybash's patch",
        "commit": values["commit"],
        "patch_sha256": sha256(patch),
        "rust": values["rust"],
        "wasm_bindgen": values["bindgen"],
    }


def built(out):
    """The build's files, checked against its own SHA256SUMS and the size limits."""
    sums = {}
    for line in (out / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        sums[name.strip()] = digest
    files = {}
    for name in FILES:
        data = (out / name).read_bytes()
        if len(data) > MOST.get(name, DEFAULT_MOST):
            raise SystemExit(f"{name} is larger than allowed")
        if sums.get(name) != sha256(data):
            raise SystemExit(f"{name} does not match the build's SHA256SUMS")
        files[name] = data
    return files


def vendor(out, target, check, repo=REPO):
    files = built(out)
    manifest = pin(repo)
    manifest["files"] = {name: sha256(data) for name, data in files.items()}
    files["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    if check:
        present = sorted(p.name for p in target.iterdir()) if target.is_dir() else []
        if present != sorted(files):
            raise SystemExit(f"vendored files differ: {present}")
        for name, data in files.items():
            if (target / name).read_bytes() != data:
                raise SystemExit(f"vendored {name} is not the build's")
        return manifest
    target.mkdir(parents=True, exist_ok=True)
    for stale in target.iterdir():
        if stale.name not in files:
            stale.unlink()
    for name, data in files.items():
        (target / name).write_bytes(data)
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--vendor", type=Path, default=REPO / "web/vendor/ironrdp")
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    manifest = vendor(args.out, args.vendor, args.check)
    verb = "Verified" if args.check else "Vendored"
    print(f"{verb} IronRDP {manifest['commit'][:12]}: wasm {manifest['files']['ironrdp_web_bg.wasm'][:12]}")


if __name__ == "__main__":
    main()
