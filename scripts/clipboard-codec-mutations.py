"""Both-direction fault injection on the actual native conversion source.

Only new disposable builder files are written. A normal sanitized test must
pass before/after these variants; neither variant is acceptance evidence.
"""
from pathlib import Path
import os
import resource
import shlex
import signal
import subprocess
import sys

lab = Path(sys.argv[1])
if not lab.is_dir() or not str(lab).startswith(("/tmp/keybash-native.", "/tmp/keybash-native-build.")):
    raise SystemExit("codec mutation stage refused")
stage = lab / "clipboard-mutations"
stage.mkdir()
source = Path("native/clipboard.c").read_text()
test = Path("native/clipboard_test.c").read_bytes()
cflags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "winpr3"], text=True))
libs = shlex.split(subprocess.check_output(["pkg-config", "--libs", "winpr3"], text=True))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
for name, before, after, assertion in (
    ("accept", "return 0;", "return 1;", "!keybash_clipboard_to_utf8"),
    ("refuse", "return 1;", "return 0;", "keybash_clipboard_from_utf8(text"),
):
    directory = stage / name
    directory.mkdir()
    if before not in source:
        raise SystemExit("codec mutation anchor changed")
    (directory / "clipboard.c").write_text(source.replace(before, after))
    (directory / "clipboard_test.c").write_bytes(test)
    binary = directory / "codec.test"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer", *cflags, str(directory / "clipboard_test.c"), "-o", str(binary), *libs], check=True, timeout=30)
    result = subprocess.run([str(binary)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=10, env={**os.environ, "WLOG_LEVEL": "OFF"})
    if result.returncode != -signal.SIGABRT or assertion not in result.stdout:
        raise SystemExit("codec mutation did not fail its intended assertion: " + result.stdout[-16000:])
    print("Native clipboard " + name + " mutation detected by intended assertion", flush=True)
