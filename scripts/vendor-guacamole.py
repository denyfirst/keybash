"""Bundle unmodified Apache JS modules; verify the official archive before use."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import tarfile
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--archive", type=Path)
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
expected = "81f9fd5a7b4377fb0ee295d0d4fec92e9667f2aafaa3d0ed8937f535deabdee4"
archive = args.archive.read_bytes() if args.archive else urllib.request.urlopen(
    "https://archive.apache.org/dist/guacamole/1.6.0/source/guacamole-client-1.6.0.tar.gz",
    timeout=120).read(32 * 1024 * 1024)
if hashlib.sha256(archive).hexdigest() != expected:
    raise SystemExit("Guacamole source archive digest mismatch")
prefix = "guacamole-client-1.6.0/"
modules = prefix + "guacamole-common-js/src/main/webapp/modules/"
files = {}
with tarfile.open(fileobj=io.BytesIO(archive)) as source:
    names = sorted(m.name for m in source.getmembers()
                   if m.isfile() and m.name.startswith(modules) and m.name.endswith(".js"))
    if len(names) != 35:
        raise SystemExit("Guacamole module inventory changed")
    parts = []
    for name in names:
        data = source.extractfile(name).read()
        if len(data) > 256 * 1024:
            raise SystemExit("Guacamole module size changed")
        files[name.removeprefix(modules)] = hashlib.sha256(data).hexdigest()
        parts.append(data)
    outputs = {"guacamole.mjs": b"\n;\n".join(parts) + b"\nexport { Guacamole };\n"}
    for name in ["LICENSE", "NOTICE"]:
        outputs["guacamole-" + name + ".txt"] = source.extractfile(prefix + name).read()
manifest = {"project": "Apache guacamole-common-js", "version": "1.6.0",
            "archive_sha256": expected, "modules": files,
            "files": {name: hashlib.sha256(data).hexdigest() for name, data in outputs.items()}}
outputs["guacamole-manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
vendor = Path(__file__).resolve().parents[1] / "web/vendor"
for name, data in outputs.items():
    path = vendor / name
    if args.check:
        if path.read_bytes() != data:
            raise SystemExit("Guacamole bundled bytes changed: " + name)
    else:
        path.write_bytes(data)
print("Verified Apache Guacamole 1.6.0 local JS assets")
