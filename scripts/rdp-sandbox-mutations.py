"""Create two disposable Go overlays; never edit the candidate source/runtime.

The public preflight sends no native select/connect instruction or credentials.
The unchanged helper must refuse an allow-all syscall filter, and an unusable
deny-all filter must fail the same positive preflight. Normal tests run again
without overlays after both expected failures.
"""
import json
from pathlib import Path
import sys

prefix = Path(sys.argv[1])
if not str(prefix).startswith("/tmp/keybash-native.") or prefix.name != "prefix" or not prefix.is_dir():
    raise SystemExit("mutation prefix refused")
path = Path.cwd() / "internal/rdplab/runtime_linux_amd64.go"
original = path.read_text()
start = original.index("func rdpSeccomp() []byte {")
end = original.index("\nfunc startRDPProcess(", start)
stage = prefix.parent / "sandbox-mutations"
stage.mkdir()
for name, action in (("allow", "unix.SECCOMP_RET_ALLOW"), ("refuse", "unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)")):
    body = """func rdpSeccomp() []byte {
        var raw bytes.Buffer
        _ = binary.Write(&raw, binary.LittleEndian, []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: ACTION}})
        return raw.Bytes()
    }
""".replace("ACTION", action)
    output = stage / (name + ".go")
    output.write_text(original[:start] + body + original[end:])
    (stage / (name + ".json")).write_text(json.dumps({"Replace": {str(path): str(output)}}))
