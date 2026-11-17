"""RustSec advisories against the crates a build really compiled.

  rust-advisories.py built < cargo-json-messages > BUILT.txt
      Lists "name version" for every crate cargo compiled, read from
      `cargo build --message-format=json-render-diagnostics`.
  rust-advisories.py check --built BUILT.txt AUDIT.json
      Reads `cargo audit --json` for a whole lock. An advisory of any kind
      (vulnerability, unsound, unmaintained, yanked) on a compiled crate fails,
      unless REVIEWED names it with the reason it does not apply. Advisories on
      crates the build never compiled are listed, not fatal: IronRDP's lock also
      holds its native tools and tests.
"""
import argparse
import json
import sys

# Advisory ID -> the crate it was reviewed for, with the reason beside it.
REVIEWED = {
    # rsa (the Marvin timing attack, no fixed release): it needs RSA
    # decryption or signing with a private key. The browser client holds none,
    # and never uses RDP standard security, since the proxy does TLS and NLA
    # with Windows itself. The proxy holds none either: it signs in with NTLM,
    # and Windows' TLS signature is checked with ring (rdp-proxy/src/pin.rs).
    "RUSTSEC-2023-0071": "rsa",
}


def package_name_version(package_id):
    """Cargo's package ID spec: "source#name@version", or "path#version" when
    the name is the path's last part."""
    left, sep, right = package_id.rpartition("#")
    if not sep or not left or not right:
        raise ValueError("unreadable package id")
    if "@" in right:
        name, _, version = right.partition("@")
    else:
        name, version = left.rstrip("/").rsplit("/", 1)[-1], right
    if not name or not version or any(c.isspace() for c in name + version):
        raise ValueError("unreadable package id")
    return name, version


def built(lines):
    seen = set()
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        message = json.loads(line)
        if message.get("reason") == "compiler-artifact":
            seen.add(package_name_version(message["package_id"]))
    if not seen:
        raise SystemExit("no compiled crate in cargo's messages")
    return sorted(seen)


def findings(audit):
    """(id, kind, name, version, title) for every advisory in an audit report."""
    out = []
    vulnerabilities = audit["vulnerabilities"]["list"]
    if not isinstance(vulnerabilities, list):
        raise ValueError("unreadable audit report")
    entries = [("vulnerability", entry) for entry in vulnerabilities]
    for kind, items in audit.get("warnings", {}).items():
        if not isinstance(items, list):
            raise ValueError("unreadable audit report")
        entries += [(kind, entry) for entry in items]
    for kind, entry in entries:
        package, advisory = entry["package"], entry.get("advisory") or {}
        out.append((advisory.get("id") or "(no advisory)", kind, package["name"], package["version"], advisory.get("title", "")))
    return out


def check(built_rows, audit):
    compiled = set(built_rows)
    fatal = 0
    for id, kind, name, version, title in sorted(findings(audit)):
        if (name, version) not in compiled:
            state = "not built"
        elif REVIEWED.get(id) == name:
            state = "built, reviewed"
        else:
            state = "BUILT"
            fatal += 1
        print(f"{state:16} {id:18} {kind:13} {name} {version}: {title}"[:200])
    return fatal


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("built")
    checker = sub.add_parser("check")
    checker.add_argument("--built", required=True)
    checker.add_argument("audit")
    args = parser.parse_args()
    if args.command == "built":
        for name, version in built(sys.stdin):
            print(name, version)
        return
    with open(args.built, encoding="utf-8") as f:
        rows = [tuple(line.split()) for line in f if line.strip()]
    if not rows or any(len(row) != 2 for row in rows):
        raise SystemExit("unreadable list of compiled crates")
    with open(args.audit, encoding="utf-8") as f:
        audit = json.load(f)
    fatal = check(rows, audit)
    if fatal:
        raise SystemExit(f"{fatal} advisories reach crates the build compiled")


if __name__ == "__main__":
    main()
