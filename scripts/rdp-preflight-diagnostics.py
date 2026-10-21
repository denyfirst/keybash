"""CI failure-only overlays for PUBLIC-ONLY preflight. Never acceptance evidence.

Original sources/binaries remain intact. No native select/connect or credential
is sent by the selected diagnostic test. Overlays print only fixed preparation
refusal numbers and fixed bwrap/setpriv setup diagnostics.
"""
import json
from pathlib import Path
import sys

prefix = Path(sys.argv[1])
if not str(prefix).startswith("/tmp/keybash-native.") or prefix.name != "prefix" or not prefix.is_dir():
    raise SystemExit("diagnostic prefix refused")
repo = Path.cwd()
stage = prefix.parent / "preflight-diagnostics"
stage.mkdir()
changes = {}
for name in ("runtime_linux_amd64.go", "worker_linux_amd64.go", "manager_native_linux_test.go"):
    path = repo / "internal/rdplab" / name
    text = path.read_text()
    if name == "runtime_linux_amd64.go":
        anchor = "cmd.Stdin, cmd.Stdout, cmd.Stderr = input, output, io.Discard"
        if text.count(anchor) != 1:
            raise SystemExit("diagnostic runtime anchor changed")
        text = text.replace(anchor, "cmd.Stdin, cmd.Stdout, cmd.Stderr = input, output, os.Stderr")
    elif name == "worker_linux_amd64.go":
        text = text.replace('"context"', '"context"\n"fmt"', 1)
        start = text.index("func RunNativeWorker(")
        end = text.index("\nfunc relayRDP", start)
        function = text[start:end]
        count = 0
        while "return errNative" in function:
            count += 1
            function = function.replace("return errNative", f'fmt.Fprintln(os.Stderr,"KB_PUBLIC_PREPARATION_{count}"); return diagnosticError', 1)
        function = function.replace("diagnosticError", "errNative")
        text = text[:start] + function + text[end:]
    else:
        text = text.replace('"bin/keybash-rdp-worker"', '"bin/debug-worker"')
    output = stage / name
    output.write_text(text)
    changes[str(path)] = str(output)
(stage / "overlay.json").write_text(json.dumps({"Replace": changes}))
