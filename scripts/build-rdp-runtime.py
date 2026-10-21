"""Build an empty-stage, source-test runtime from an already verified prefix.

Run on the disposable Ubuntu builder only. Does not install/start any service.
No shell evaluation, external downloads, customer inputs or release signing.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--prefix", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
prefix, output = args.prefix.resolve(strict=True), args.output
if not output.is_absolute() or output.exists() or output != output.resolve():
    raise SystemExit("runtime stage must be a new absolute directory")
output.mkdir(mode=0o755)
pending, copied = [], set()


def copy(source, destination):
    source = Path(source)
    if destination in copied:
        return
    if not source.is_file() or source.stat().st_size > 64 * 1024 * 1024:
        raise SystemExit("runtime input refused")
    target = output / destination.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)  # dereference builder symlinks; no runtime symlinks
    target.chmod(0o755 if os.access(source, os.X_OK) else 0o644)
    copied.add(destination)
    pending.append(source)


copy(prefix / "sbin/guacd", "/opt/keybash-rdp/sbin/guacd")
for source in sorted((prefix / "lib").rglob("*.so*")):
    if source.is_file() and (source.name.startswith(("libguac", "libfreerdp3", "libwinpr3")) or source.parent.name == "freerdp3"):
        copy(source, "/opt/keybash-rdp/" + source.relative_to(prefix).as_posix())
copy("/usr/bin/setpriv", "/setpriv")

while pending:
    source = pending.pop()
    # ldd is executed only on binaries built from the pinned verified source,
    # or trusted builder OS libraries. This is not an untrusted ELF inspector.
    result = subprocess.run(["/usr/bin/ldd", str(source)], capture_output=True, text=True, check=True)
    for line in result.stdout.splitlines():
        if "not found" in line:
            raise SystemExit("unresolved native dependency")
        match = re.search(r"(?:=>\s+)?(/[^\s]+)\s+\(0x[0-9a-f]+\)", line)
        if not match:
            if line.strip().startswith("linux-vdso.so."):
                continue
            if line.strip() == "statically linked":
                dynamic = subprocess.run(["/usr/bin/readelf", "--dynamic", "--wide", str(source)], capture_output=True, text=True, check=True)
                if "(NEEDED)" not in dynamic.stdout:
                    continue
            raise SystemExit("unrecognized native dependency inventory: " + source.name + ": " + line[:256])
        dependency = Path(match[1])
        if dependency.is_relative_to(prefix):
            destination = "/opt/keybash-rdp/" + dependency.relative_to(prefix).as_posix()
        elif str(dependency).startswith(("/lib/", "/lib64/", "/usr/lib/")):
            destination = str(dependency)
        else:
            raise SystemExit("unexpected native dependency path")
        copy(dependency, destination)

# Mountpoints exist before the root filesystem is bound read-only. Namespace
# setup must never create host files in the approved runtime at launch time.
for name in ("proc", "dev", "tmp", "run/keybash"):
    (output / name).mkdir(parents=True, exist_ok=True)
for name in ("worker", "run/keybash/approved.pem", "run/keybash/name"):
    (output / name).write_bytes(b"mountpoint\n")
    (output / name).chmod(0o644)
for directory in output.rglob("*"):
    if directory.is_dir():
        directory.chmod(0o755)
print("Minimal source-test RDP runtime staged; no service installed.")
