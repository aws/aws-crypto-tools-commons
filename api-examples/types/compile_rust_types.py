#!/usr/bin/env python3
"""Try each type in rust-types.json on each option, and write what compiled to the dashboard page data.

  compile_rust_types.py --rust-repo <aws-crypto-tools-rust checkout>

It builds one scratch crate that depends on aws-esdk and aws-crypto-mpl from the checkout.
For each option, it tries each held type with each fix, keeps the cheapest fix that compiled,
and writes the rows to dashboard/api-examples/types.json.
"""
import argparse
import json
import re
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path

import rust_types

HERE = Path(__file__).resolve().parent
PAGE = HERE.parent.parent / "dashboard" / "api-examples" / "types.json"

READ_ALL = "{ let mut r = x; let mut v = Vec::new(); std::io::Read::read_to_end(&mut r, &mut v).unwrap(); v }"
# Fixes to try for each kind of held type, as (cost, code, how).
# Cost 0 passes the value as is, 1 adds & or Some, 2 adds one call, 3 or more adds several calls.
# "set" passes the code to set_<option>, which takes an Option. "pair" passes two values, x and y.
FIXES = {
    "bytes": [(0, "x", "base"), (1, "&x", "base"), (1, "&x[..]", "base"), (2, "x.clone()", "base"),
              (2, "x.to_vec()", "base"), (2, "x.as_ref()", "base"), (2, "x.into_inner()", "base"),
              (3, "x.as_ref().to_vec()", "base"), (1, "Some(x)", "set"), (2, "Some(x.to_vec())", "set")],
    "optional bytes": [(0, "x", "set"), (2, "x.map(Into::into)", "set"), (2, "x.map(|b| b.to_vec())", "set"),
                       (3, "x.map(|b| b.clone().into_inner())", "set"), (3, "x.map(|b| b.into_inner())", "set"),
                       (3, "x.unwrap()", "base"), (3, "x.unwrap().as_ref()", "base"),
                       (3, "x.unwrap().into_inner()", "base"), (3, "&x.unwrap().into_inner()", "base")],
    "stream": [(3, "x.bytes().unwrap()", "base"), (4, "x.bytes().unwrap().to_vec()", "base"),
               (5, "&x.collect().await.unwrap().into_bytes()", "base"),
               (6, "x.collect().await.unwrap().into_bytes().to_vec()", "base")],
    "text": [(0, "x", "base"), (1, "&x", "base"), (2, "x.clone()", "base"), (2, "x.to_string()", "base"),
             (2, "x.as_str()", "base"), (2, "x.as_bytes()", "base"), (3, "x.as_bytes().to_vec()", "base"),
             (1, "Some(x)", "set"), (2, "Some(x.to_string())", "set")],
    "optional text": [(0, "x", "set"), (2, "x.map(Into::into)", "set"), (3, "x.map(|s| s.to_string())", "set"),
                      (3, "x.unwrap()", "base"), (3, "x.unwrap().as_bytes()", "base")],
    "path": [(3, "std::fs::read(x).unwrap()", "base"), (4, "&std::fs::read(x).unwrap()", "base")],
    "reader": [(5, READ_ALL, "base"), (6, "&" + READ_ALL, "base")],
    "number": [(0, "x", "base"), (2, "x.into()", "base"), (3, "x.try_into().unwrap()", "base"),
               (3, "std::time::Duration::from_secs(x.into())", "base"),
               (4, "std::time::Duration::from_secs(x.try_into().unwrap())", "base")],
    "duration": [(0, "x", "base"), (2, "x.as_secs()", "base"), (3, "x.as_secs().try_into().unwrap()", "base")],
    "list": [(1, "Some(x)", "set"), (2, "Some(x.to_vec())", "set"),
             (3, "Some(x.iter().map(|s| s.to_string()).collect())", "set")],
    "optional list": [(0, "x", "set"), (3, "x.map(|v| v.iter().map(|s| s.to_string()).collect())", "set")],
    "map": [(1, "Some(x)", "set"), (2, "Some(x.into())", "set"), (3, "Some(x.clone().into())", "set"),
            (3, "Some(x.into_iter().collect())", "set"),
            (4, "Some(x.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())", "set")],
    "pair": [(0, "x, y", "pair"), (1, "&x, &y", "pair"), (2, "x.to_string(), y.to_string()", "pair")],
    "named": [(0, "x", "base"), (2, "x.clone()", "base"), (3, "(*x).clone()", "base"), (1, "Some(x)", "set")],
}
BYTES_LIKE = ["bytes", "optional bytes", "stream", "text", "optional text", "path", "reader"]
TEXT_LIKE = ["text", "optional text"]
MPL = "aws_crypto_mpl::keyring::"
# Each option: page key, code that starts the call, the part of it the page already shows, setter, kinds.
OPTIONS = [
    ("mpl/RawAesKeyring.wrapping_key", MPL + "RawAesKeyring::builder()", None, "wrapping_key", BYTES_LIKE),
    ("mpl/RawAesKeyring.key_name", MPL + "RawAesKeyring::builder()", None, "key_name", TEXT_LIKE),
    ("mpl/AwsKmsKeyring.kms_key_id", MPL + "AwsKmsKeyring::builder()", None, "kms_key_id", TEXT_LIKE),
    ("mpl/AwsKmsKeyring.kms_client", MPL + "AwsKmsKeyring::builder()", None, "kms_client",
     ["named aws_sdk_kms::Client"]),
    ("mpl/AwsKmsKeyring.grant_tokens", MPL + "AwsKmsKeyring::builder()", None, "grant_tokens",
     TEXT_LIKE + ["list", "optional list"]),
    ("mpl/HierarchicalKeyring.ttl", MPL + "HierarchicalKeyring::builder()", None, "ttl", ["duration", "number"]),
    ("mpl/HierarchicalKeyring.branch_key_id", MPL + "HierarchicalKeyring::builder()", None, "branch_key_id",
     TEXT_LIKE),
    ("esdk/encrypt.plaintext", "client.encrypt()", "client", "plaintext", BYTES_LIKE),
    ("esdk/decrypt.ciphertext", "client.decrypt()", "client", "ciphertext", BYTES_LIKE),
    ("esdk/encrypt.encryption_context", "client.encrypt()", "client", "encryption_context", ["map", "pair"]),
    ("esdk/encrypt.frame_length", "client.encrypt()", "client", "frame_length", ["number"]),
    ("esdk/Client.max_encrypted_data_keys", "aws_esdk::Client::builder()", None, "max_encrypted_data_keys",
     ["number"]),
]


class Scratch:
    """A scratch crate next to the checkout's crates, reusing esdk's build output."""

    def __init__(self, rust_repo, crates):
        self.dir = Path(tempfile.mkdtemp(prefix="rust-types-compile-"))
        self.target = Path(rust_repo) / "esdk" / "target"
        # No default features, so each crate builds with the features our crates already ask for.
        deps = "\n".join(f'{name} = {{ version = "*", default-features = false }}' for name in sorted(crates))
        (self.dir / "Cargo.toml").write_text(
            '[package]\nname = "rust-types-compile"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n'
            '[lib]\npath = "lib.rs"\n\n[workspace]\n\n[dependencies]\n'
            f'aws-esdk = {{ path = "{rust_repo}/esdk" }}\naws-crypto-mpl = {{ path = "{rust_repo}/mpl" }}\n{deps}\n')
        shutil.copy(Path(rust_repo) / "esdk" / "Cargo.lock", self.dir / "Cargo.lock")

    def errors(self, lines):
        """Line numbers in `lines`, counting from 0, that failed to compile."""
        (self.dir / "lib.rs").write_text("#![allow(warnings)]\n" + "\n".join(lines) + "\n")
        out = subprocess.run(["cargo", "build", "--lib", "--message-format=json", "--target-dir", str(self.target)],
                             cwd=self.dir, capture_output=True, text=True)
        failed = set()
        for raw in out.stdout.splitlines():
            msg = json.loads(raw) if raw.startswith("{") else {}
            if msg.get("reason") != "compiler-message" or msg["message"]["level"] != "error":
                continue
            for span in msg["message"]["spans"]:
                if span["is_primary"] and span["file_name"].endswith("lib.rs"):
                    failed.add(span["line_start"] - 2)
        if out.returncode != 0 and not failed:
            raise SystemExit(out.stderr[-3000:])
        return failed


def locked_crates(rust_repo):
    """crates.io crates that esdk already builds, by the name code uses for them."""
    lock = tomllib.loads((Path(rust_repo) / "esdk" / "Cargo.lock").read_text())
    return {p["name"].replace("-", "_"): p["name"] for p in lock["package"] if "source" in p}


NAME = r"(?<![\w:])([A-Za-z_]\w*)(?![\w:])"  # a name with no path in front or behind it


def bare_names(ty):
    """Names in a type that still need a path, like Blob in Option<&Blob>."""
    return [n for n in re.findall(NAME, ty) if n not in rust_types.PRELUDE]


def named_types(path):
    """Held types for an option that takes one named type: the type, a borrow, an Arc, and what builds it.

    What builds it comes from the type's one-value constructors, like aws_sdk_kms::Client::new(&SdkConfig).
    It also returns where each name in our dependencies lives, for the constructors' parameter types.
    """
    crate_ident, name = path.split("::")[0], path.split("::")[-1]
    short = crate_ident.removeprefix("aws_sdk_")
    lock = json.loads(rust_types.LOCK.read_text())
    scanner = rust_types.build_scanner()
    defines, ctors = {}, []
    for crate in lock["crates"]:
        if "ours" not in crate["groups"]:
            continue
        ident = crate["name"].replace("-", "_")
        for row in rust_types.scan(scanner, crate):
            if "defines" in row:
                defines.setdefault(row["defines"], set()).update({f"{ident}::{row['defines']}", row["path"]})
            elif ident == crate_ident and row.get("ctor") == name:
                ctors.append((row["fn"], row["param"]))
    label = f"{short}::{name}"
    held = [(label, path, "named", FIXES["named"]), (f"&{label}", f"&{path}", "named", FIXES["named"]),
            (f"Arc<{label}>", f"std::sync::Arc<{path}>", "named", FIXES["named"])]
    for fn, param in sorted(ctors):
        owned = rust_types.unref(param)
        shown, ty = owned, owned
        # A name the type's own crate defines, like Config, gets that crate's path.
        for n in bare_names(owned):
            home = sorted((p for p in defines.get(n, ()) if p.startswith(crate_ident + "::")), key=len)
            if home:
                shown = re.sub(rf"(?<![\w:]){n}(?![\w:])", f"{short}::{n}", shown)
                ty = re.sub(rf"(?<![\w:]){n}(?![\w:])", home[0], ty)
        held.append((shown, ty, "ctor", [(3, f"{path}::{fn}({'&x' if param.startswith('&') else 'x'})", "base")]))
        if param.startswith("&"):
            held.append(("&" + shown, "&" + ty, "ctor", [(3, f"{path}::{fn}(x)", "base")]))
    return held, defines


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rust-repo", required=True)
    args = parser.parse_args()
    rust_repo = str(Path(args.rust_repo).resolve())
    data = json.loads(rust_types.OUT.read_text())
    kept = {kind: [r["type"] for r in rows if r["kept"]] for kind, rows in data["kinds"].items()}
    paths = {name: list(found) for name, found in data["paths"].items()}
    in_lock = locked_crates(rust_repo)

    # Held types per option: (label, type, kind, fixes).
    per_option = {}
    for key, recv, shown, setter, kinds in OPTIONS:
        held = []
        for kind in kinds:
            if kind.startswith("named "):
                found, defines = named_types(kind.split(" ", 1)[1])
                held += found
                for name, candidates in defines.items():
                    merged = set(paths.get(name, ())) | candidates
                    paths[name] = sorted(merged, key=lambda p: (p.count("::"), p))
            elif kind == "pair":
                held += [(f"({t}, {t})", t, "pair", FIXES["pair"]) for t in kept.get("text", [])]
            else:
                held += [(t, t, kind, FIXES[kind]) for t in kept.get(kind, [])]
        per_option[key] = held

    # Find a path that works for each name, trying the shortest first. Standard library names are known.
    needed = {n for held in per_option.values() for _, ty, _, _ in held for n in bare_names(ty)}
    tries = [(n, p) for n in sorted(needed - set(rust_types.STD_PATHS)) for p in paths.get(n, [])
             if p.split("::")[0] in in_lock]
    crates = {in_lock[p.split("::")[0]] for _, p in tries}
    crates |= {in_lock[p.split("::")[0]] for held in per_option.values() for _, ty, _, _ in held
               for p in re.findall(r"\b(\w+)::", ty) if p in in_lock}
    scratch = Scratch(rust_repo, crates)
    failed = scratch.errors([f"use {p} as Name{i};" for i, (_, p) in enumerate(tries)])
    chosen = dict(rust_types.STD_PATHS)
    for i, (n, p) in enumerate(tries):
        if i not in failed:
            chosen.setdefault(n, p)

    def code(ty):
        if any(n not in chosen for n in bare_names(ty)):
            return None
        return re.sub(NAME, lambda m: chosen.get(m.group(1), m.group(1)), ty)

    # Drop types that still do not compile as a parameter type, then try every fix.
    trials, lines = [], []
    for key, recv, shown, setter, _ in OPTIONS:
        params = "client: &aws_esdk::Client, " if recv.startswith("client") else ""
        for label, ty, kind, fixes in per_option[key]:
            expr = code(ty)
            if expr is None:
                continue
            for cost, glue, how in fixes:
                call = f"{recv}.set_{setter}({glue})" if how == "set" else f"{recv}.{setter}({glue})"
                arg = f"x: {expr}, y: {expr}" if how == "pair" else f"x: {expr}"
                # Only fixes that await need an async fn. An async fn rejects types with a hidden lifetime.
                asyncness = "async " if ".await" in glue else ""
                lines.append(f"{asyncness}fn t{len(trials)}({params}{arg}) {{ let _ = {call}; }}")
                shown_call = call[len(shown):] if shown else call[len(recv):]
                trials.append((key, label, kind, cost, shown_call))
    failed = scratch.errors(lines)
    rows = {}
    for n, (key, label, kind, cost, call) in enumerate(trials):
        best = rows.setdefault(key, {}).setdefault(label, [label, None, "", kind])
        if n not in failed and (best[1] is None or cost < best[1]):
            best[1], best[2] = cost, call
    shutil.rmtree(scratch.dir)

    page = json.loads(PAGE.read_text())
    page["rust"] = {key: sorted(found.values(), key=lambda r: (r[1] is None, r[1] or 0, r[0]))
                    for key, found in rows.items()}
    commit = subprocess.run(["git", "-C", rust_repo, "rev-parse", "--short", "HEAD"], capture_output=True,
                            text=True, check=True).stdout.strip()
    page["note"] = (f"Rust: {len(trials):,} tries compiled on aws-crypto-tools-rust at {commit}. "
                    f"Types: api-examples/types/rust-types.json, from {data['lock']['crates']} crates pinned on "
                    f"{data['lock']['refreshed']}. Other languages: the latest released signatures, not compiled. "
                    "Customers: public GitHub code.")
    PAGE.write_text(json.dumps(page, indent=2, ensure_ascii=False) + "\n")
    print(f"{len(trials)} tries, {len(trials) - len(failed)} compiled")


if __name__ == "__main__":
    main()
