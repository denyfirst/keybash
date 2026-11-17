"""Check the licence of every crate a Rust package builds with, for one target.

Runs `cargo metadata` on an already fetched, locked workspace and walks the
package's normal and build dependencies (not dev-dependencies). Each crate's
SPDX expression must be satisfiable from licences that combine into Keybash's
AGPL-3.0. A crate without an expression, or with any other licence, stops the
build until a person reviews it. Prints "name version licence", sorted.
"""
import argparse
import json
import re
import subprocess
import sys

# Every one of these can be combined into AGPL-3.0 code.
ALLOWED = {
    "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSL-1.0", "CC0-1.0", "ISC",
    "MIT", "MIT-0", "MPL-2.0", "Unicode-3.0", "Unicode-DFS-2016", "Unlicense", "Zlib",
}
EXCEPTIONS = {"LLVM-exception"}
TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9.+-]+)")


def tokens(expression):
    # Old crates write "MIT/Apache-2.0" for "MIT OR Apache-2.0".
    text, out, at = expression.replace("/", " OR "), [], 0
    while at < len(text):
        if text[at:].strip() == "":
            break
        match = TOKEN.match(text, at)
        if not match:
            raise ValueError("unreadable licence expression")
        out.append(match.group(1))
        at = match.end()
    return out


def allowed(expression):
    """True when the SPDX expression can be met with allowed licences only."""
    items, at = tokens(expression), 0

    def take(word=None):
        nonlocal at
        if at >= len(items) or (word and items[at] != word):
            raise ValueError("malformed licence expression")
        at += 1
        return items[at - 1]

    def single():
        if at < len(items) and items[at] == "(":
            take("(")
            value = either()
            take(")")
            return value
        name = take()
        if name in ("AND", "OR", "WITH", ")"):
            raise ValueError("malformed licence expression")
        ok = name in ALLOWED
        if at < len(items) and items[at] == "WITH":
            take("WITH")
            exception = take()
            ok = ok and exception in EXCEPTIONS
        return ok

    def both():
        value = single()
        while at < len(items) and items[at] == "AND":
            take("AND")
            value = single() and value
        return value

    def either():
        value = both()
        while at < len(items) and items[at] == "OR":
            take("OR")
            value = both() or value
        return value

    result = either()
    if at != len(items):
        raise ValueError("malformed licence expression")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    raw = subprocess.run(
        ["cargo", "metadata", "--locked", "--offline", "--format-version", "1",
         "--manifest-path", args.manifest, "--filter-platform", args.target],
        capture_output=True, check=True,
    ).stdout
    metadata = json.loads(raw)
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    roots = [id for id, package in packages.items() if package["name"] == args.package and package["source"] is None]
    if len(roots) != 1:
        raise SystemExit("package not found once in the workspace")
    seen, pending = set(), roots[:]
    while pending:
        id = pending.pop()
        if id in seen:
            continue
        seen.add(id)
        for dep in nodes[id]["deps"]:
            if any(kind["kind"] in (None, "build") for kind in dep["dep_kinds"]):
                pending.append(dep["pkg"])
    refused, rows = [], []
    for id in seen:
        package = packages[id]
        licence = package.get("license") or ""
        try:
            ok = bool(licence) and allowed(licence)
        except ValueError:
            ok = False
        rows.append(f"{package['name']} {package['version']} {licence or '(none)'}")
        if not ok:
            refused.append(rows[-1])
    if refused:
        print("licences not allowed without review:", *sorted(refused), sep="\n  ", file=sys.stderr)
        raise SystemExit(1)
    print(*sorted(rows), sep="\n")


if __name__ == "__main__":
    main()
