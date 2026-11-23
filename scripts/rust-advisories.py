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
    # chrono (unmaintained, informational: no known flaw, no fixed release).
    # IronRDP's web crate links it only to switch on its wasmbind feature
    # (`extern crate chrono as _`); nothing in IronRDP's lock depends on it or
    # calls it, so none of its code is reachable in the browser module. Drop
    # this line when IronRDP drops the crate (the freshness check watches its
    # releases).
    "RUSTSEC-2026-0543": "chrono",
    # heapless 0.7.17 (nine "unsound" advisories of 18 November 2026, fixed
    # only from 0.9.4). It comes only through iso7816 0.1.4, which winscard
    # (sspi's smart-card emulation) uses, and iso7816 requires heapless 0.7, so
    # no update can reach a fixed release. Each advisory names the functions
    # affected: spsc, index_map, deque, history_buf, sorted_linked_list and the
    # pools, and Vec's IntoIter drop when an element's own drop panics.
    # iso7816 uses only heapless::Vec<u8, N> (new, try_from, writing bytes); a
    # u8 has no drop, so none of these is reached. And neither the proxy nor
    # the page signs in with a smart card: the proxy uses NTLM with the stored
    # password, the page no CredSSP at all. Drop these lines when sspi or
    # iso7816 moves to heapless 0.9.4 or later.
    "RUSTSEC-2026-0574": "heapless",
    "RUSTSEC-2026-0575": "heapless",
    "RUSTSEC-2026-0576": "heapless",
    "RUSTSEC-2026-0577": "heapless",
    "RUSTSEC-2026-0578": "heapless",
    "RUSTSEC-2026-0579": "heapless",
    "RUSTSEC-2026-0580": "heapless",
    "RUSTSEC-2026-0581": "heapless",
    "RUSTSEC-2026-0582": "heapless",
    # url 2.5.8 (a stack overflow in Url::origin on nested blob: URLs, of 20
    # November 2026, fixed in 2.5.9). The proxy's own lock takes 2.5.9; this
    # line is for the browser module, which IronRDP's lock at the pinned
    # commit builds with 2.5.8. Nothing compiled calls Url::origin or
    # url::quirks::origin: the crates that use url (ironrdp-web,
    # ironrdp-connector and sspi) only parse a Kerberos KDC address, and the
    # page never gives one. Drop this line when IronRDP's lock moves to url
    # 2.5.9 or later (the freshness check watches its releases).
    "RUSTSEC-2026-0592": "url",
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
