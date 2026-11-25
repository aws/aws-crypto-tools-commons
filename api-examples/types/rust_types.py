#!/usr/bin/env python3
"""List the Rust types that customers hold, from the public APIs of real crates.

  rust_types.py refresh --rust-repo <aws-crypto-tools-rust checkout>
      Ask crates.io which crates to read, and pin them in rust-types.lock.json.
  rust_types.py build
      Download the pinned crates, read their public signatures with rust-scan, and write rust-types.json.

The lock pins each crate's version and checksum, so build gives the same output every time.
Run refresh only to move to newer crates.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import tarfile
import time
import urllib.request
from collections import defaultdict
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOCK = HERE / "rust-types.lock.json"
OUT = HERE / "rust-types.json"
SCAN = HERE / "rust-scan"
CACHE = Path(os.environ.get("RUST_TYPES_CACHE", Path.home() / ".cache" / "crypto-tools-api-examples"))
AGENT = "aws-crypto-tools-commons api-examples (https://github.com/aws/aws-crypto-tools-commons)"

# Each group is one crates.io query, so the choice of crates comes from data.
GROUPS = {
    "top": "The 100 most-downloaded crates. Their types make the Rust list.",
    "crypto": "The 50 most-downloaded crates in the cryptography category. Their types make the crypto list.",
    "aws": "The 25 most-downloaded crates that aws-sdk-rust-ci publishes, plus our dependencies it publishes. "
           "Their types make the AWS list.",
    "ours": "The crates.io dependencies of aws-crypto-mpl and aws-esdk. The compile step needs their type paths "
            "and constructors.",
}
# Per list: (group, types kept per kind, crates a type needs to be kept).
LISTS = {"rust": ("top", 8, 3), "aws": ("aws", 3, 2), "crypto": ("crypto", 1, 3)}
MIN_KEPT = 2  # The Rust list's top types of a kind are kept with only 2 crates.
LISTED = 15  # Types listed per kind, kept or not, so a reader can see what just missed.

INTS = {"u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize"}
POINTERS = {"Box", "Cow", "Arc", "Rc"}
MAPS = {"HashMap", "BTreeMap", "IndexMap"}
READ_TRAITS = {"Read", "BufRead", "AsyncRead"}
MADE_FROM_BYTES = {"From<Vec<u8>>", "From<Bytes>", "From<&[u8]>", "From<Box<[u8]>>"}
# Standard library types that implement Read. The scan reads crates.io crates, not the standard library.
STD_READERS = {"File", "Stdin", "StdinLock", "TcpStream", "UnixStream", "ChildStdout", "ChildStderr", "Cursor",
               "BufReader", "Empty", "Repeat", "Chain", "Take"}
# Where standard library names live, so the compile step can name them.
STD_PATHS = {
    "Cow": "std::borrow::Cow", "Arc": "std::sync::Arc", "Rc": "std::rc::Rc",
    "HashMap": "std::collections::HashMap", "BTreeMap": "std::collections::BTreeMap",
    "Path": "std::path::Path", "PathBuf": "std::path::PathBuf", "File": "std::fs::File",
    "Duration": "std::time::Duration", "Read": "std::io::Read", "BufRead": "std::io::BufRead",
    "BufReader": "std::io::BufReader", "Cursor": "std::io::Cursor", "Stdin": "std::io::Stdin",
    "StdinLock": "std::io::StdinLock", "Empty": "std::io::Empty", "Repeat": "std::io::Repeat",
    "Chain": "std::io::Chain", "Take": "std::io::Take", "TcpStream": "std::net::TcpStream",
    "UnixStream": "std::os::unix::net::UnixStream", "ChildStdout": "std::process::ChildStdout",
    "ChildStderr": "std::process::ChildStderr",
}
# Names Rust code can use without a path.
PRELUDE = {"Vec", "String", "Box", "Option", "str", "char", "bool", "dyn", "impl", "mut", "Item", "Target"} | INTS


def http_get(url):
    request = urllib.request.Request(url, headers={"User-Agent": AGENT})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def crates_api(path):
    time.sleep(1)  # crates.io asks for at most one request a second.
    return json.loads(http_get("https://crates.io/api/v1/" + path))


def index_path(name):
    name = name.lower()
    if len(name) <= 2:
        return f"{len(name)}/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def checksum(name, version):
    for line in http_get("https://index.crates.io/" + index_path(name)).decode().splitlines():
        entry = json.loads(line)
        if entry["vers"] == version:
            return entry["cksum"]
    raise SystemExit(f"{name} {version} is not in the crates.io index")


def our_dependencies(rust_repo):
    import tomllib  # Python 3.11 or newer. Only refresh needs it.

    names = set()
    for crate in ("mpl", "esdk"):
        manifest = tomllib.loads((Path(rust_repo) / crate / "Cargo.toml").read_text())
        for name, spec in manifest.get("dependencies", {}).items():
            if not (isinstance(spec, dict) and "path" in spec):
                names.add(name)
    return sorted(names)


def refresh(rust_repo):
    picked = {}

    def take(group, crates):
        for c in crates:
            entry = picked.setdefault(c["name"], {
                "name": c["name"],
                "version": c["max_stable_version"] or c["newest_version"],
                "downloads": c["downloads"],
                "groups": [],
            })
            entry["groups"].append(group)

    take("top", crates_api("crates?sort=downloads&per_page=100")["crates"])
    take("crypto", crates_api("crates?category=cryptography&sort=downloads&per_page=50")["crates"])
    aws_user = crates_api("users/aws-sdk-rust-ci")["user"]
    take("aws", crates_api(f"crates?user_id={aws_user['id']}&sort=downloads&per_page=25")["crates"])
    for name in our_dependencies(rust_repo):
        take("ours", [crates_api(f"crates/{name}")["crate"]])
        owners = {user["login"] for user in crates_api(f"crates/{name}/owner_user")["users"]}
        if aws_user["login"] in owners and "aws" not in picked[name]["groups"]:
            picked[name]["groups"].append("aws")
    for entry in picked.values():
        entry["cksum"] = checksum(entry["name"], entry["version"])
    commit = subprocess.run(["git", "-C", rust_repo, "rev-parse", "HEAD"], capture_output=True, text=True,
                            check=True).stdout.strip()
    lock = {
        "refreshed": date.today().isoformat(),
        "aws_crypto_tools_rust_commit": commit,
        "groups": GROUPS,
        "crates": sorted(picked.values(), key=lambda e: e["name"]),
    }
    LOCK.write_text(json.dumps(lock, indent=1) + "\n")
    print(f"pinned {len(picked)} crates in {LOCK.name}")


def fetch(crate):
    name, version = crate["name"], crate["version"]
    folder = CACHE / "crates" / f"{name}-{version}"
    archive = CACHE / "crates" / f"{name}-{version}.crate"
    if not archive.exists():
        archive.parent.mkdir(parents=True, exist_ok=True)
        archive.write_bytes(http_get(f"https://static.crates.io/crates/{name}/{name}-{version}.crate"))
    if hashlib.sha256(archive.read_bytes()).hexdigest() != crate["cksum"]:
        archive.unlink()
        raise SystemExit(f"{name} {version} does not match the checksum in the lock")
    if not folder.is_dir():
        with tarfile.open(archive) as tar:
            tar.extractall(CACHE / "crates", filter="data")
    return folder


def build_scanner():
    target = CACHE / "rust-scan-target"
    subprocess.run(["cargo", "build", "--release", "--locked", "--quiet", "--manifest-path",
                    str(SCAN / "Cargo.toml"), "--target-dir", str(target)], check=True)
    return target / "release" / "rust-types-scan"


def scan(scanner, crate):
    """The lines rust-scan prints for one pinned crate, as dicts."""
    out = subprocess.run([str(scanner), crate["name"], str(fetch(crate))], capture_output=True, text=True,
                         check=True).stdout
    return [json.loads(line) for line in out.splitlines()]


def split_type(text):
    """Split `HashMap<String, Vec<u8>>` into ("HashMap", ["String", "Vec<u8>"])."""
    if "<" not in text or not text.endswith(">"):
        return text, []
    base, inner = text.split("<", 1)
    return base, split_list(inner[:-1])


def split_list(text):
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(text[start:i].strip())
            start = i + 1
    if text[start:].strip():
        parts.append(text[start:].strip())
    return parts


def unref(text):
    return text[1:] if text.startswith("&") and not text.startswith("&mut ") else text


class Evidence:
    """What scanned trait impls say a third-party type holds.

    Rust only lets a crate implement a foreign trait like AsRef for its own types, so each impl names the
    defining crate. A bare name counts only when every crate that defines it has the impl, so a `Tag` that
    is bytes in one crate does not make every `Tag` bytes.
    """

    def __init__(self, impls, definers, aliases):
        found = defaultdict(lambda: defaultdict(set))  # kind -> name -> crates with the impl
        deref = defaultdict(dict)  # wrapper name -> crate -> Deref target, like "_" for Zeroizing<_>
        # name -> (crate, trait) for each impl that decided its kind, so the page can say why it is listed.
        self.traits = defaultdict(set)
        for crate, trait, ty in impls:
            base = ty.split("<")[0]
            if trait in ("AsRef<[u8]>", "Deref<Target = [u8]>", "Borrow<[u8]>"):
                found["bytes"][base].add(crate)
            elif trait in ("AsRef<str>", "Deref<Target = str>", "Borrow<str>"):
                found["text"][base].add(crate)
            elif trait == "AsRef<Path>":
                found["path"][base].add(crate)
            elif trait in READ_TRAITS:
                found["reader"][base].add(crate)
            elif trait in MADE_FROM_BYTES:
                found["made from bytes"][base].add(crate)
            elif trait in ("Deref<Target = _>", "Deref<Target = [_]>") and "<" in ty:
                deref[base][crate] = trait[len("Deref<Target = "):-1]
            else:
                continue
            self.traits[base].add((crate, trait))
        self.holds = {kind: {name for name, crates in names.items() if crates >= definers.get(name, crates)}
                      for kind, names in found.items()}
        self.holds = defaultdict(set, self.holds)
        # A type made from bytes that cannot be read as bytes, like ByteStream, is a stream to read out.
        self.holds["stream"] = self.holds.pop("made from bytes", set()) - self.holds["bytes"]
        self.deref = {name: next(iter(targets.values())) for name, targets in deref.items()
                      if set(targets) >= definers.get(name, set(targets)) and len(set(targets.values())) == 1}
        # An alias with the same name must point at the same kind, like uuid's `type Bytes = [u8; 16]`.
        for kind in ("bytes", "text", "path", "reader", "stream"):
            self.holds.setdefault(kind, set())
        for kind, names in list(self.holds.items()):
            names -= {n for n in names if any(not is_kind(t, kind, self) for t in aliases.get(n, ()))}

    def why(self, t, crate_names):
        """Which impl made a third-party type in `t` count, like "aws-types implements AsRef<str> for AppName".

        crate_names maps a crate's code name, like aws_types, to its crates.io name. None for std types.
        """
        for name in names_in(t):
            counted = any(name in names for names in self.holds.values()) or name in self.deref
            if not counted or not self.traits[name]:
                continue
            crate, trait = sorted(self.traits[name])[0]
            crate = crate_names.get(crate, crate)
            if trait.startswith("Deref<Target = _"):
                return f"{crate} implements Deref for {name}, so a {name} reads as the value inside it."
            if name in self.holds["stream"]:
                return f"{crate} implements {trait} for {name}, but nothing that lends its bytes, so it is a stream."
            return f"{crate} implements {trait} for {name}."
        return None

    def wraps(self, text, kind):
        """True for a wrapper like Zeroizing<Vec<u8>> whose Deref target is the kind."""
        base, args = split_type(text)
        target = self.deref.get(base)
        if not args or target is None:
            return False
        if target == "_":
            return is_kind(args[0], kind, self)
        return kind == "bytes" and target == "[_]" and args[0] == "u8"


def is_kind(text, kind, ev):
    base, args = split_type(text)
    if kind == "bytes":
        if text in ("[u8]", "Vec<u8>") or re.fullmatch(r"\[u8; \d+\]", text):
            return True
        if base in POINTERS and args and args[-1] in ("[u8]", "Vec<u8>"):
            return True
    if kind == "text":
        if text in ("str", "String", "char"):
            return True
        if base in POINTERS and args and args[-1] in ("str", "String"):
            return True
    if kind == "path" and text in ("Path", "PathBuf"):
        return True
    if kind == "reader":
        if base in STD_READERS:
            return True
        if base == "Box" and args and args[0].startswith("dyn ") and args[0][4:].split(" + ")[0] in READ_TRAITS:
            return True
    if not args and base in ev.holds[kind]:
        return True
    return kind in ("bytes", "text") and ev.wraps(text, kind)


def classify(t, ev):
    """The kind of value a customer holds, or None when the type is not one we try."""
    if "_" in t or "; N]" in t or t.startswith(("impl ", "dyn ", "&dyn ")):
        return None
    inner = unref(t)
    for kind in ("bytes", "text", "path", "reader", "stream"):
        if is_kind(inner, kind, ev):
            return kind
    if inner in INTS:
        return "number"
    if inner == "Duration":
        return "duration"
    base, args = split_type(inner)
    if base == "Option" and len(args) == 1 and not t.startswith("&"):
        kind = classify(args[0], ev)
        return f"optional {kind}" if kind in ("bytes", "text", "list") else None
    if base in MAPS and len(args) == 2 and all(is_kind(unref(a), "text", ev) for a in args):
        return "map"
    if inner.startswith("("):
        parts = split_list(inner[1:-1])
        if len(parts) == 2 and all(is_kind(unref(p), "text", ev) for p in parts):
            return "pair"
        return None
    element = None
    if base == "Vec" and len(args) == 1:
        element = args[0]
    elif inner.startswith("["):
        element = inner[1:-1].rsplit(";", 1)[0].strip()
    if element is not None:
        if is_kind(unref(element), "text", ev):
            return "list"
        if classify(element, ev) == "pair":
            return "map"
    return None


def accepted_kind(t, ev):
    """The kind an `impl Trait` parameter accepts, like bytes for impl AsRef<[u8]>."""
    bound = t[len("impl "):].split(" + ")[0]
    name, args = split_type(bound)
    if name in READ_TRAITS:
        return "reader"
    for arg in args:
        arg = arg.split(" = ")[-1]
        for kind in ("bytes", "text", "path"):
            if is_kind(unref(arg), kind, ev):
                return kind
    return None


def names_in(t):
    return [n for n in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", t) if n not in PRELUDE and n not in STD_PATHS]


def summary(doc):
    """The part of a doc comment the page shows: the first paragraph, plus the next one when the first is short.

    A markdown link keeps only its text, so [`Region`](crate::Region) becomes `Region`.
    """
    paragraphs = [p.strip() for p in doc.split("\n\n") if p.strip()]
    if not paragraphs:
        return ""
    text = paragraphs[0]
    if len(text) < 60 and len(paragraphs) > 1:
        text = text.rstrip(".") + ". " + paragraphs[1]
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\[[^\]]*\]", r"\1", text)
    text = re.sub(r"\[(`[^`]+`)\]", r"\1", text)
    if len(text) > 300:
        cut = text[:300]
        end = cut.rfind(". ")
        text = cut[:end + 1] if end > 0 else cut.rsplit(" ", 1)[0] + " ..."
    return text


def build():
    lock_text = LOCK.read_text()
    lock = json.loads(lock_text)
    scanner = build_scanner()
    # "held" counts crates that hand the type out (return types and fields); "takes" counts parameters.
    seen = defaultdict(lambda: {"held": set(), "takes": set(), "param": 0, "return": 0, "field": 0})
    defines = defaultdict(set)
    definers = defaultdict(set)
    aliases = defaultdict(set)
    impls = set()
    downloads = {c["name"]: c["downloads"] for c in lock["crates"]}
    versions = {c["name"]: c["version"] for c in lock["crates"]}
    crate_names = {c["name"].replace("-", "_"): c["name"] for c in lock["crates"]}
    # (type, crate, pos) -> the first place the crate has that type there, for the page's example links.
    sites = {}
    # name -> where each crate defines it, with its doc comment.
    docs = defaultdict(list)
    parse_errors = 0
    for crate in lock["crates"]:
        ident = crate["name"].replace("-", "_")
        for row in scan(scanner, crate):
            if "pos" in row:
                entry = seen[row["type"]]
                entry["takes" if row["pos"] == "param" else "held"].add(crate["name"])
                entry[row["pos"]] += row["count"]
                sites[(row["type"], crate["name"], row["pos"])] = {k: row[k] for k in ("item", "file", "line")}
            elif "defines" in row:
                defines[row["defines"]].update({f"{ident}::{row['defines']}", row["path"]})
                docs[row["defines"]].append({"crate": crate["name"], "version": crate["version"], "path": row["path"],
                                             "doc": summary(row.get("doc", "")), "file": row["file"],
                                             "line": row["line"]})
                if "alias" in row:
                    aliases[row["defines"]].add(row["alias"])
                else:
                    definers[row["defines"]].add(ident)
            elif "impl" in row:
                impls.add((ident, row["impl"], row["for"]))
            elif "parse_errors" in row:
                parse_errors += row["parse_errors"]
    ev = Evidence(impls, definers, aliases)
    lists = {name: {c["name"] for c in lock["crates"] if group in c["groups"]}
             for name, (group, _, _) in LISTS.items()}
    scanned = set().union(*lists.values())

    def count(t, side, where):
        return len(seen[t][side] & lists[where])

    def entry(t, side):
        crates = sorted(seen[t][side] & scanned, key=lambda n: (-downloads[n], n))
        row = {"type": t}
        row.update({f"{name}_crates": count(t, side, name) for name in LISTS})
        for pos in (("param",) if side == "takes" else ("return", "field")):
            row[pos] = seen[t][pos]
        row["seen_in"] = crates[:3]
        return row

    def ranked(types, side, where):
        return sorted(types, key=lambda t: (-count(t, side, where), t))

    held = defaultdict(list)
    accepts = defaultdict(list)
    for t, e in seen.items():
        kind = classify(t, ev)
        if kind and e["held"] & scanned:
            held[kind].append(t)
        if e["takes"] & scanned:
            kind = accepted_kind(t, ev) if t.startswith("impl ") else kind
            if kind:
                accepts[kind].append(t)
    # Of the fixed-size byte arrays, keep only the length most crates use, so one size stands for them.
    arrays = [t for t in held["bytes"] if re.fullmatch(r"\[u8; \d+\]", t)]
    if arrays:
        common = max(arrays, key=lambda t: (len(seen[t]["held"] & scanned), t))
        held["bytes"] = [t for t in held["bytes"] if not re.fullmatch(r"&?\[u8; \d+\]", t) or unref(t) == common]
    kinds = {}
    kept = []
    for kind in sorted(held):
        chosen = {}
        listed = []
        for name, (_, keep, min_crates) in LISTS.items():
            order = ranked(held[kind], "held", name)
            listed += order[:LISTED if name == "rust" else keep + 2]
            for rank, t in enumerate(t for t in order if t not in chosen):
                if rank >= keep:
                    break
                n = count(t, "held", name)
                if n >= min_crates or (name == "rust" and rank < MIN_KEPT and n >= 2):
                    chosen[t] = name
        rows = []
        for t in dict.fromkeys(listed):
            row = entry(t, "held")
            row["kept"] = chosen.get(t)
            if row["kept"]:
                # One place in each named crate that hands the type out, so a reader can see how it is used.
                row["examples"] = [next({"crate": c, "version": versions[c], "pos": pos, **sites[(t, c, pos)]}
                                        for pos in ("return", "field") if (t, c, pos) in sites)
                                   for c in row["seen_in"]]
                why = ev.why(t, crate_names)
                if why:
                    row["why"] = why
            rows.append(row)
        kinds[kind] = rows
        kept.extend(chosen)
    # Where each name in a kept type may live. The compile step tries them in this order.
    paths = {name: sorted(defines[name], key=lambda p: (p.count("::"), p))
             for name in sorted(set(names_in(" ".join(kept)))) if defines.get(name)}
    out = {
        "generated_by": "api-examples/types/rust_types.py build",
        "lock": {"file": LOCK.name, "refreshed": lock["refreshed"], "crates": len(lock["crates"]),
                 "sha256": hashlib.sha256(lock_text.encode()).hexdigest()},
        "rules": [
            "A type is held when a pub fn returns it, with one Result layer removed, or a pub field has it.",
            "A type is accepted when it is a pub fn parameter.",
            "Each type counts once per crate, and types rank by how many crates use them.",
            *[f"From the {name} list, keeps the top {keep} held types of each kind, not kept already, that "
              f"show up in at least {min_crates} crates." for name, (_, keep, min_crates) in LISTS.items()],
            f"The Rust list's top {MIN_KEPT} types of a kind need only 2 crates.",
            "A third-party type is bytes, text, a path or a reader when its crate implements AsRef, Deref, "
            "Borrow, Read or AsyncRead for it with that target. It is a stream when it is made From bytes "
            "but has no such impl.",
            "Of the fixed-size byte arrays, only the most common length is kept.",
            "Skips generic types, &mut types, and arrays whose length is a name.",
        ],
        "parse_errors": parse_errors,
        "kinds": kinds,
        "accepts": {k: [entry(t, "takes") for t in sorted(v, key=lambda t: (-len(seen[t]["takes"] & scanned), t))[:LISTED]]
                    for k, v in sorted(accepts.items())},
        "paths": paths,
        # Where each name in a kept type is defined, with the start of its doc comment.
        "docs": {name: docs[name] for name in paths},
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    print(f"read {len(lock['crates'])} crates, {len(seen)} types, {parse_errors} files failed to parse")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    refresh_parser = sub.add_parser("refresh")
    refresh_parser.add_argument("--rust-repo", required=True)
    sub.add_parser("build")
    args = parser.parse_args()
    if args.command == "refresh":
        refresh(args.rust_repo)
    else:
        build()


if __name__ == "__main__":
    main()
