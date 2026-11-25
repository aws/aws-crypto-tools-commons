#!/usr/bin/env python3
"""Try each type in rust-types.json on each option, and write what compiled to the dashboard page data.

  compile_rust_types.py --rust-repo <aws-crypto-tools-rust checkout>

It builds one scratch crate that depends on aws-esdk and aws-crypto-mpl from the checkout.
For each option, it tries each held type with each fix, keeps the cheapest fix that compiled,
and writes the rows to dashboard/api-examples/types.json.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import calls
import rust_about
import rust_runs
import rust_types

HERE = Path(__file__).resolve().parent
PAGE = HERE.parent.parent / "dashboard" / "api-examples" / "types.json"

READ_ALL = "{ let mut r = x; let mut v = Vec::new(); std::io::Read::read_to_end(&mut r, &mut v).unwrap(); v }"
# Fixes to try for each kind of held type, as (code, how). A fix's cost is its number of calls (calls.py).
# "set" passes the code to set_<option>, which takes an Option. "pair" passes two values, x and y.
# Every kind tries x as is, even where no setter takes it today, so a proposed setter that takes it shows.
# When two fixes have the same cost, the one listed first wins.
FIX_CODE = {
    "bytes": [("x", "base"), ("&x", "base"), ("&x[..]", "base"), ("x.clone()", "base"), ("x.to_vec()", "base"),
              ("x.as_ref()", "base"), ("x.into_inner()", "base"), ("x.as_ref().to_vec()", "base"),
              ("Some(x)", "set"), ("Some(x.to_vec())", "set")],
    "optional bytes": [("x", "set"), ("x.map(Into::into)", "set"), ("x.map(|b| b.to_vec())", "set"),
                       ("x.map(|b| b.clone().into_inner())", "set"), ("x.map(|b| b.into_inner())", "set"),
                       ("x.unwrap()", "base"), ("x.unwrap().as_ref()", "base"), ("x.unwrap().into_inner()", "base"),
                       ("&x.unwrap().into_inner()", "base")],
    "stream": [("x", "base"), ("x.bytes().unwrap()", "base"), ("x.bytes().unwrap().to_vec()", "base"),
               ("&x.collect().await.unwrap().into_bytes()", "base"),
               ("x.collect().await.unwrap().into_bytes().to_vec()", "base")],
    "text": [("x", "base"), ("&x", "base"), ("x.clone()", "base"), ("x.to_string()", "base"), ("x.as_str()", "base"),
             ("x.as_bytes()", "base"), ("x.as_bytes().to_vec()", "base"), ("Some(x)", "set"),
             ("Some(x.to_string())", "set")],
    "optional text": [("x", "set"), ("x.map(Into::into)", "set"), ("x.map(|s| s.to_string())", "set"),
                      ("x.unwrap()", "base"), ("x.unwrap().as_bytes()", "base")],
    "path": [("x", "base"), ("std::fs::read(x).unwrap()", "base"), ("&std::fs::read(x).unwrap()", "base")],
    "reader": [("x", "base"), (READ_ALL, "base"), ("&" + READ_ALL, "base")],
    "number": [("x", "base"), ("x.into()", "base"), ("x.try_into().unwrap()", "base"),
               ("std::time::Duration::from_secs(x.into())", "base"),
               ("std::time::Duration::from_secs(x.try_into().unwrap())", "base")],
    "duration": [("x", "base"), ("x.as_secs()", "base"), ("x.as_secs().try_into().unwrap()", "base")],
    "list": [("x", "base"), ("&x", "base"), ("Some(x)", "set"), ("Some(x.to_vec())", "set"),
             ("Some(x.iter().map(|s| s.to_string()).collect())", "set")],
    "optional list": [("x", "set"), ("x.map(|v| v.iter().map(|s| s.to_string()).collect())", "set")],
    "map": [("x", "base"), ("&x", "base"), ("Some(x)", "set"), ("Some(x.into())", "set"),
            ("Some(x.clone().into())", "set"), ("Some(x.into_iter().collect())", "set"),
            ("Some(x.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())", "set")],
    "pair": [("x, y", "pair"), ("&x, &y", "pair"), ("x.to_string(), y.to_string()", "pair")],
    "named": [("x", "base"), ("x.clone()", "base"), ("(*x).clone()", "base"), ("Some(x)", "set")],
}


def with_costs(fixes):
    """(cost, code, how) for each (code, how), where the cost is the fix's number of calls."""
    return [(calls.count(code), code, how) for code, how in fixes]


FIXES = {kind: with_costs(fixes) for kind, fixes in FIX_CODE.items()}
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


TRIALS = HERE / "rust_trials.rs"
RUNS = HERE / "rust_runs.rs"
RUNS_SUPPORT = HERE / "rust_runs_support.rs"
TRIALS_HEADER = [
    "// Generated by api-examples/types/compile_rust_types.py. Each fn passes one held type to one option with one",
    "// fix. The types page links each Rust cell to the fn here that compiled. Don't edit by hand.",
    "#![allow(warnings)]",
]
# The line of the first trial fn in rust_trials.rs.
TRIALS_FIRST_LINE = len(TRIALS_HEADER) + 1


class Scratch:
    """A scratch crate next to the checkout's crates, reusing esdk's build output."""

    def __init__(self, rust_repo, crates):
        self.dir = Path(tempfile.mkdtemp(prefix="rust-types-compile-"))
        self.target = Path(rust_repo) / "esdk" / "target"
        # No default features, so each crate builds with the features our crates already ask for.
        deps = "\n".join(f'{name} = {{ version = "*", default-features = false }}'
                         for name in sorted(crates - {"tokio"}))
        (self.dir / "Cargo.toml").write_text(
            '[package]\nname = "rust-types-compile"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n'
            '[lib]\npath = "lib.rs"\n\n[workspace]\n\n[dependencies]\n'
            f'aws-esdk = {{ path = "{rust_repo}/esdk" }}\naws-crypto-mpl = {{ path = "{rust_repo}/mpl" }}\n{deps}\n\n'
            '[dev-dependencies]\ntokio = { version = "*", default-features = false, features = ["rt", "macros"] }\n')
        shutil.copy(Path(rust_repo) / "esdk" / "Cargo.lock", self.dir / "Cargo.lock")

    def cargo(self, *args, env=None):
        # Cargo's own options go before "--". The ones after it go to the test binary.
        args = list(args)
        split = args.index("--") if "--" in args else len(args)
        command = ["cargo", *args[:split], "--target-dir", str(self.target), *args[split:]]
        return subprocess.run(command, cwd=self.dir, capture_output=True, text=True, env={**os.environ, **(env or {})})

    def errors(self, lines):
        """The lines in `lines`, counting from 0, that failed to compile, each with the compiler's messages."""
        (self.dir / "lib.rs").write_text(trials_text(lines))
        out = self.cargo("build", "--lib", "--message-format=json")
        failed = {}
        for line, message in compiler_errors(out, "lib.rs"):
            failed.setdefault(line - TRIALS_FIRST_LINE, []).append(message)
        if out.returncode != 0 and not failed:
            raise SystemExit(out.stderr[-3000:])
        return failed

    def run_tests(self, text):
        """Compile and run the tests in `text` one at a time. Returns (stdout, {line: [error]})."""
        tests = self.dir / "tests"
        (tests / "runs").mkdir(parents=True, exist_ok=True)
        shutil.copy(RUNS_SUPPORT, tests / "runs" / "support.rs")
        (tests / "runs.rs").write_text(text)
        # The trials that failed would stop the tests from building, so the tests get an empty lib.
        (self.dir / "lib.rs").write_text("")
        built = self.cargo("test", "--test", "runs", "--no-run", "--message-format=json")
        failed = {}
        for line, message in compiler_errors(built, "runs.rs"):
            failed.setdefault(line, []).append(message)
        if failed:
            return "", failed
        if built.returncode != 0:
            raise SystemExit(built.stderr[-3000:])
        # The tests write their files to the temp folder. This one is in the crate, so remove() deletes them.
        temp = self.dir / "tmp"
        temp.mkdir(exist_ok=True)
        ran = self.cargo("test", "--test", "runs", "--", "--test-threads=1", "--nocapture", env={"TMPDIR": str(temp)})
        return ran.stdout, {}

    def remove(self):
        shutil.rmtree(self.dir)


def trials_text(lines):
    return "\n".join(TRIALS_HEADER + lines) + "\n"


def compiler_errors(out, file_name):
    """(line, rendered message) for each compiler error whose main span is in file_name."""
    for raw in out.stdout.splitlines():
        msg = json.loads(raw) if raw.startswith("{") else {}
        if msg.get("reason") != "compiler-message" or msg["message"]["level"] != "error":
            continue
        for span in msg["message"]["spans"]:
            if span["is_primary"] and span["file_name"].endswith(file_name):
                yield span["line_start"], msg["message"]["rendered"]


def locked_crates(rust_repo):
    """crates.io crates that esdk already builds, by the name code uses for them."""
    import tomllib  # Python 3.11 or newer.

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
    defines, ctors, docs = {}, [], {}
    for crate in lock["crates"]:
        if "ours" not in crate["groups"]:
            continue
        ident = crate["name"].replace("-", "_")
        for row in rust_types.scan(scanner, crate):
            if "defines" in row:
                defines.setdefault(row["defines"], set()).update({f"{ident}::{row['defines']}", row["path"]})
                docs.setdefault(row["defines"], []).append(
                    {"crate": crate["name"], "version": crate["version"], "path": row["path"],
                     "doc": rust_types.summary(row.get("doc", "")), "file": row["file"], "line": row["line"]})
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
        as_is = [("x", "base"), ("&x", "base")]
        build = (f"{path}::{fn}({'&x' if param.startswith('&') else 'x'})", "base")
        held.append((shown, ty, "ctor", with_costs(as_is + [build])))
        if param.startswith("&"):
            held.append(("&" + shown, "&" + ty, "ctor", with_costs(as_is[:1] + [(f"{path}::{fn}(x)", "base")])))
    return held, defines, docs


def prepare(rust_repo, extra_code=""):
    """Held types for each option as (label, Rust type, kind, fixes), a scratch crate that can name them, and
    where each name in them is defined, with its doc comment.

    Types whose names have no working path are left out. Crates that `extra_code` names become
    dependencies of the scratch crate too.
    """
    data = json.loads(rust_types.OUT.read_text())
    kept = {kind: [r["type"] for r in rows if r["kept"]] for kind, rows in data["kinds"].items()}
    paths = {name: list(found) for name, found in data["paths"].items()}
    docs = {name: list(found) for name, found in data.get("docs", {}).items()}
    in_lock = locked_crates(rust_repo)

    # Held types per option: (label, type, kind, fixes).
    per_option = {}
    for key, recv, shown, setter, kinds in OPTIONS:
        held = []
        for kind in kinds:
            if kind.startswith("named "):
                found, defines, named_docs = named_types(kind.split(" ", 1)[1])
                held += found
                for name, entries in named_docs.items():
                    docs.setdefault(name, []).extend(e for e in entries if e not in docs[name])
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
    crates |= {in_lock[p] for p in re.findall(r"\b(\w+)::", extra_code) if p in in_lock}
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

    held = {key: [(label, code(ty), kind, fixes) for label, ty, kind, fixes in found if code(ty)]
            for key, found in per_option.items()}
    return held, scratch, docs


def trial(n, params, expr, how, glue, call, note=""):
    """One line that compiles a call: a fn taking the held value as x, and as y too for a pair."""
    arg = f"x: {expr}, y: {expr}" if how == "pair" else f"x: {expr}"
    # Only fixes that await need an async fn. An async fn rejects types with a hidden lifetime.
    asyncness = "async " if ".await" in glue else ""
    return f"{asyncness}fn t{n}({params}{arg}) {{ let _ = {call}; }}" + (f" // {note}" if note else "")


def setter_trials(held):
    """Trials of every fix on each option's real setter, and their lines.

    Each trial is (key, label, Rust type, kind, cost, how, glue, call as the page shows it).
    """
    trials, lines = [], []
    for key, recv, shown, setter, _ in OPTIONS:
        params = "client: &aws_esdk::Client, " if recv.startswith("client") else ""
        for label, expr, kind, fixes in held[key]:
            for cost, glue, how in fixes:
                call = f"{recv}.set_{setter}({glue})" if how == "set" else f"{recv}.{setter}({glue})"
                lines.append(trial(len(trials), params, expr, how, glue, call, f"{key}: {label}"))
                trials.append((key, label, expr, kind, cost, how, glue,
                               call[len(shown):] if shown else call[len(recv):]))
    return trials, lines


def best_rows(trials, failed):
    """For each option, each held type's cheapest call that compiled.

    A row is {type, calls, code, kind, trial}: the number of calls, the call, and the line of its fn in
    rust_trials.rs. calls is None when no fix compiled.
    """
    rows = {}
    for n, (key, label, _, kind, cost, _, _, call) in enumerate(trials):
        best = rows.setdefault(key, {}).setdefault(label, {"type": label, "calls": None, "code": "", "kind": kind,
                                                           "trial": None})
        if n not in failed and (best["calls"] is None or cost < best["calls"]):
            best.update(calls=cost, code=call, trial=TRIALS_FIRST_LINE + n)
    order = lambda r: (r["calls"] is None, r["calls"] or 0, r["type"])  # noqa: E731
    return {key: sorted(found.values(), key=order) for key, found in rows.items()}


def receivers():
    """{option: (code that starts a run's call, the part between it and the setter)}."""
    out = {}
    for key, recv, shown, _, _ in OPTIONS:
        if shown == "client":
            out[key] = ("aws_esdk::Client::default()", recv[len(shown):])
        else:
            out[key] = (recv, "")
    return out


def run_checks(scratch, rows, trials):
    """Run a test for each row whose call compiled, and add what it found to the row.

    A test that doesn't compile is left out and says so, so one bad test doesn't stop the rest.
    Returns the text of rust_runs.rs.
    """
    # A test that doesn't compile tries again inline, then is skipped.
    modes = {}
    for _ in range(3):
        text, tests = rust_runs.write(rows, trials, receivers(), TRIALS_FIRST_LINE, modes)
        stdout, failed = scratch.run_tests(text)
        if not failed:
            break
        for name, (_, _, line) in tests.items():
            end = min((other for _, _, other in tests.values() if other > line), default=10 ** 9)
            if any(line <= bad < end for bad in failed):
                modes[name] = "skip" if modes.get(name) == "inline" else "inline"
    else:
        raise SystemExit("the run tests still don't compile:\n" + "\n".join(m for ms in failed.values() for m in ms))
    found = rust_runs.read(stdout)
    by_row = {(key, label): (name, line) for name, (key, label, line) in tests.items()}
    for key, found_rows in rows.items():
        for row in found_rows:
            if (key, row["type"]) in by_row:
                name, line = by_row[(key, row["type"])]
                row["run"] = found.get(name, {"skipped": "the test did not finish"})
                row["test"] = line
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rust-repo", required=True)
    args = parser.parse_args()
    rust_repo = str(Path(args.rust_repo).resolve())
    data = json.loads(rust_types.OUT.read_text())
    held, scratch, docs = prepare(rust_repo, RUNS_SUPPORT.read_text() + "\n".join(rust_runs.OWNED.values()))
    trials, lines = setter_trials(held)
    failed = scratch.errors(lines)
    TRIALS.write_text(trials_text(lines))
    rows = best_rows(trials, failed)
    RUNS.write_text(run_checks(scratch, rows, trials))
    scratch.remove()

    page = json.loads(PAGE.read_text())
    page["rust"] = rows
    lock = json.loads(rust_types.LOCK.read_text())
    sizes = {name: sum(group in c["groups"] for c in lock["crates"]) for name, (group, _, _) in rust_types.LISTS.items()}
    page.setdefault("about", {})["rust"] = rust_about.about(held, data, docs, sizes)
    commit = subprocess.run(["git", "-C", rust_repo, "rev-parse", "HEAD"], capture_output=True,
                            text=True, check=True).stdout.strip()
    page["rust_commit"] = commit
    # CI installs this version to compile the trials again, because another version may compile other fixes.
    version = subprocess.run(["rustc", "--version"], capture_output=True, text=True, check=True).stdout
    page["rustc"] = version.split()[1]
    page["files"] = {"trials": "api-examples/types/rust_trials.rs", "runs": "api-examples/types/rust_runs.rs",
                     "check": ".github/workflows/api-examples-types.yml"}
    runs = sum(1 for found in rows.values() for r in found if "run" in r and "skipped" not in r["run"])
    page["note"] = (f"Rust: {len(trials):,} tries compiled and {runs} calls run on aws-crypto-tools-rust at "
                    f"{commit[:7]} with rustc {page['rustc']}. Types: api-examples/types/rust-types.json, from "
                    f"{data['lock']['crates']} crates pinned on {data['lock']['refreshed']}. Other languages: the "
                    "latest released signatures, not compiled.")
    page.pop("customers", None)
    PAGE.write_text(json.dumps(page, indent=2, ensure_ascii=False) + "\n")
    print(f"{len(trials)} tries, {len(trials) - len(failed)} compiled, {runs} runs")


if __name__ == "__main__":
    main()
