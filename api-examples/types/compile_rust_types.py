#!/usr/bin/env python3
"""Try each type in rust-types.json on each option, and write what compiled to the dashboard page data.

  compile_rust_types.py --rust-repo <aws-crypto-tools-rust checkout>

It builds one scratch crate that depends on aws-esdk and aws-crypto-mpl from the checkout.
For each option, it tries each held type with each fix, keeps the cheapest fix that compiled,
and writes the rows to dashboard/api-examples/types-rust.json. CI runs it every day on the Rust repo's
main branch, and the types page loads that run's results.
"""
import argparse
import functools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import calls
import rust_about
import rust_examples
import rust_runs
import rust_types

HERE = Path(__file__).resolve().parent
PAGE = HERE.parent.parent / "dashboard" / "api-examples" / "types-rust.json"

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
LOCAL_CRATES = ("aws_crypto_mpl", "aws_esdk")
INTS = r"u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize"
# Every API and option, from rust_api.py.
API = json.loads((HERE / "rust-api.json").read_text())


def kinds_of(opt):
    """The kinds of held value to try on an option, from the type its setter takes."""
    if opt["params"] == 2:
        return ["map", "pair"] if "EncryptionContext" in (opt.get("set_takes") or "") else ["pair"]
    takes = opt["takes"]
    handle = re.search(r"IntoShared<(\w+)>", takes)
    if handle:
        return [f"component {handle.group(1)}"]
    inner = re.sub(r"^impl (?:Into|AsRef)<(.*)>$", r"\1", takes)
    inner_code = re.sub(r"^impl (?:std::convert::)?(?:Into|AsRef)<(.*)>$", r"\1", opt["takes_code"])
    if inner in ("&[u8]", "[u8]", "Vec<u8>", "Blob", "&Blob"):
        return BYTES_LIKE
    if inner in ("String", "&str", "str"):
        # grant_tokens adds one token, and set_grant_tokens takes them all.
        return TEXT_LIKE + (["list", "optional list"] if opt.get("set_takes") == "Option<Vec<String>>" else [])
    if inner == "Duration":
        return ["duration", "number"]
    if re.fullmatch(INTS, inner):
        return ["number"]
    if inner == "bool":
        return []
    return [f"named {inner_code}"]


def page_key(api, opt):
    """This script's key for an option, like mpl/RawAesKeyring.wrapping_key or esdk/encrypt.plaintext.

    The proposals skill and rust_runs.py name options this way.
    """
    return f"{api['lib']}/{api['type']}.{opt['name']}"


SMITHY = json.loads((HERE.parent / "smithy-names.json").read_text())["libraries"]


def neutral_key(api, opt):
    """The key every language shares for an option: library, API and Smithy member, like
    mpl|raw-aes-keyring|wrappingKey. smithy-names.json maps a Rust name that differs, like cmm to materialsManager."""
    camel = re.sub(r"_(\w)", lambda m: m.group(1).upper(), opt["name"])
    names = SMITHY.get(api["lib"], {}).get(api["id"], {"aliases": {}})
    return f"{api['lib']}|{api['id']}|{names['aliases'].get(camel, camel)}"


# Each option, with the code that starts its call, the part of that code the page shows as the API's call,
# and the kinds of held value to try on it.
OPTIONS = [{"key": page_key(api, opt), "neutral": neutral_key(api, opt), "start": api["start"], "strip": api["strip"],
            "setter": opt["setter"], "set": opt["set"], "ctor": opt["ctor"], "kinds": kinds_of(opt)}
           for api in API["apis"] for opt in api["options"]]


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
            # The support code may name an API that this Rust commit doesn't have.
            errors = [m for _, m in compiler_errors(built, ".rs")]
            print("the run tests don't build on this commit, so nothing runs:\n" + "\n".join(errors)[-3000:], file=sys.stderr)
            return None, {}
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


@functools.cache
def scan_ours():
    """What rust-scan finds in our crates.io dependencies: where each name is defined, with its doc comment,
    and each type's one-value constructors as {(crate, type): [(fn, parameter type)]}."""
    lock = json.loads(rust_types.LOCK.read_text())
    scanner = rust_types.build_scanner()
    defines, ctors, docs = {}, {}, {}
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
            elif "ctor" in row:
                ctors.setdefault((ident, row["ctor"]), []).append((row["fn"], row["param"]))
    return defines, ctors, docs


def component_types(handle):
    """Held types for an option that takes a component, like a keyring: each built-in one, borrowed, in an
    Arc, and the shared handle itself."""
    info = API["handles"][handle]
    path = info["path"]
    fixes = with_costs([("x", "base"), ("&x", "base"), ("x.clone()", "base"), ("(*x).clone()", "base"),
                        (f"{path}::new(x)", "base"), (f"{path}::new(x.clone())", "base"), ("Some(x)", "set"),
                        ("Some(x.clone())", "set"), (f"Some({path}::new(x))", "set")])
    held = []
    for member in info["members"] + [path]:
        name = member.split("::")[-1]
        held += [(name, member, "component", fixes), (f"&{name}", f"&{member}", "component", fixes)]
        if member != path:
            held.append((f"Arc<{name}>", f"std::sync::Arc<{member}>", "component", fixes))
    return held


def named_types(path):
    """Held types for an option that takes one named type: the type, a borrow, an Arc, and what builds it.

    What builds it comes from the type's one-value constructors, like aws_sdk_kms::Client::new(&SdkConfig).
    It also returns where each name in our dependencies lives, for the constructors' parameter types.
    A type from our own crates, like AesWrappingAlg, is just the type and a borrow.
    """
    crate_ident, name = path.split("::")[0], path.split("::")[-1]
    if crate_ident in LOCAL_CRATES:
        return [(name, path, "named", FIXES["named"]), (f"&{name}", f"&{path}", "named", FIXES["named"])], {}, {}
    short = crate_ident.removeprefix("aws_sdk_")
    defines, all_ctors, docs = scan_ours()
    ctors = all_ctors.get((crate_ident, name), [])
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
    for opt in OPTIONS:
        key, held = opt["key"], []
        for kind in opt["kinds"]:
            if kind.startswith("component "):
                held += component_types(kind.split(" ", 1)[1])
            elif kind.startswith("named "):
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


def call_of(opt, how, glue):
    """The code that passes glue to an option, or None when the option has no setter of that shape."""
    if opt["ctor"]:
        return None if how == "set" else f"{opt['start']}::{opt['ctor']}({glue})"
    setter = opt["set"] if how == "set" else opt["setter"]
    return f"{opt['start']}.{setter}({glue})" if setter else None


def shown(opt, call):
    """A call as the page shows it: after the API's own call, with our crates' paths left off."""
    return re.sub(r"\b(?:aws_crypto_mpl|aws_esdk)::(?:[a-z_]\w*::)*", "", call[len(opt["strip"]):])


def setter_trials(held):
    """Trials of every fix on each option's real setter, and their lines.

    Each trial is (key, label, Rust type, kind, cost, how, glue, call as the page shows it).
    """
    trials, lines = [], []
    for opt in OPTIONS:
        key = opt["key"]
        params = "client: &aws_esdk::Client, " if opt["start"].startswith("client") else ""
        for label, expr, kind, fixes in held[key]:
            for cost, glue, how in fixes:
                call = call_of(opt, how, glue)
                if call is None:
                    continue
                lines.append(trial(len(trials), params, expr, how, glue, call, f"{key}: {label}"))
                trials.append((key, label, expr, kind, cost, how, glue, shown(opt, call)))
    return trials, lines


def best_rows(trials, failed):
    """For each option, each held type's cheapest call that compiled.

    A row is {type, calls, code, kind, trial}: the number of calls, the call, and the line of its fn in
    rust_trials.rs. calls is None when no fix compiled.
    """
    rows = {}
    for n, (key, label, _, kind, cost, _, glue, call) in enumerate(trials):
        best = rows.setdefault(key, {}).setdefault(label, {"type": label, "calls": None, "code": "", "kind": kind,
                                                           "trial": None})
        if n not in failed and (best["calls"] is None or cost < best["calls"]):
            # fix is the part of the call that passes the value, which the page names the calls of.
            best.update(calls=cost, code=call, fix=glue, trial=TRIALS_FIRST_LINE + n)
    order = lambda r: (r["calls"] is None, r["calls"] or 0, r["type"])  # noqa: E731
    return {key: sorted(found.values(), key=order) for key, found in rows.items()}


def receivers():
    """{option: (code that starts a run's call, the part between it and the setter)}."""
    out = {}
    for opt in OPTIONS:
        if opt["strip"] == "client":
            out[opt["key"]] = ("aws_esdk::Client::default()", opt["start"][len("client"):])
        else:
            out[opt["key"]] = (opt["start"], "")
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
    if stdout is None:
        return text
    found = rust_runs.read(stdout)
    by_row = {(key, label): (name, line) for name, (key, label, line) in tests.items()}
    for key, found_rows in rows.items():
        for row in found_rows:
            if (key, row["type"]) in by_row:
                name, line = by_row[(key, row["type"])]
                row["run"] = found.get(name, {"skipped": "the test did not finish"})
                row["test"] = line
    return text


def await_variants(lines):
    """The example, and copies with .await after some of its builds, because some builders are async."""
    spots = [i for i, line in enumerate(lines) if line.strip() == ".build()?;"]
    out = []
    for mask in range(2 ** min(len(spots), 3)):
        out.append([line.replace(".build()?;", ".build().await?;") if i in spots and mask >> spots.index(i) & 1 else line
                    for i, line in enumerate(lines)])
    return out


def check_examples(scratch, held):
    """{label: code} for each held type whose example of making it compiled. See rust_examples.py."""
    enums = {name: found[0]["variants"][-1] for name, found in API["docs"].items() if found[0].get("variants")}
    ours = {name: found[0]["path"] for name, found in API["docs"].items()}
    types = {}
    for found in held.values():
        for label, expr, _, _ in found:
            types.setdefault(label, expr)
    candidates, lines = [], []
    for label, expr in sorted(types.items()):
        made = rust_examples.example(label, enums)
        for variant in await_variants(made) if made else []:
            use = rust_examples.uses(variant, ours)
            candidates.append((label, use + variant))
            lines.append(rust_examples.check_line(len(lines), variant, use, expr))
    failed = scratch.errors(lines)
    out = {}
    for n, (label, code) in enumerate(candidates):
        if n not in failed:
            out.setdefault(label, "\n".join(code).replace(".build().await?;", ".build()\n    .await?;"))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rust-repo", required=True)
    parser.add_argument("--out", type=Path, default=PAGE)
    args = parser.parse_args()
    rust_repo = str(Path(args.rust_repo).resolve())
    data = json.loads(rust_types.OUT.read_text())
    extra = RUNS_SUPPORT.read_text() + "\n".join(rust_runs.OWNED.values()) + Path(rust_examples.__file__).read_text()
    held, scratch, docs = prepare(rust_repo, extra)
    trials, lines = setter_trials(held)
    failed = scratch.errors(lines)
    TRIALS.write_text(trials_text(lines))
    rows = best_rows(trials, failed)
    RUNS.write_text(run_checks(scratch, rows, trials))
    examples = check_examples(scratch, held)
    scratch.remove()

    lock = json.loads(rust_types.LOCK.read_text())
    sizes = {name: sum(group in c["groups"] for c in lock["crates"]) for name, (group, _, _) in rust_types.LISTS.items()}
    for name, entries in API["docs"].items():
        docs.setdefault(name, []).extend({**e, "doc": rust_types.summary(e["doc"])} for e in entries)
    about = rust_about.about(held, data, docs, sizes)
    # A component's own API builds it.
    builds = {a["type"]: a for a in API["apis"]}
    for label, entry in about.items():
        made = builds.get(label.lstrip("&").removeprefix("Arc<").rstrip(">"))
        if made and "held" not in entry:
            entry["held"] = {"text": f"You build one with {made['shown']}, on the {made['name']} tab.", "why": None,
                             "examples": []}
    commit = subprocess.run(["git", "-C", rust_repo, "rev-parse", "HEAD"], capture_output=True,
                            text=True, check=True).stdout.strip()
    rustc = subprocess.run(["rustc", "--version"], capture_output=True, text=True, check=True).stdout.split()[1]
    runs = sum(1 for found in rows.values() for r in found if "run" in r and "skipped" not in r["run"])
    neutral = {o["key"]: o["neutral"] for o in OPTIONS}
    out = {
        "generated_by": "api-examples/types/compile_rust_types.py",
        "rust_commit": commit,
        "rustc": rustc,
        "files": {"trials": "api-examples/types/rust_trials.rs", "runs": "api-examples/types/rust_runs.rs"},
        "note": (f"Rust: {len(trials):,} tries compiled and {runs} calls run on aws-crypto-tools-rust at {commit[:7]} "
                 f"with rustc {rustc}. Types: api-examples/types/rust-types.json, from {data['lock']['crates']} "
                 f"crates pinned on {data['lock']['refreshed']}."),
        # Each API and option, in rust-api.json's order. key is the one every language shares, and rust_key is
        # the one the proposals skill uses.
        "apis": [{"lib": a["lib"], "id": a["id"], "name": a["name"], "group": a["group"], "call": a["shown"],
                  "options": [{"key": neutral_key(a, o), "rust_key": page_key(a, o), "name": o["name"],
                               "takes": o["takes"], "doc": o.get("doc", "")} for o in a["options"]]}
                 for a in API["apis"]],
        "rows": {neutral[key]: found for key, found in rows.items()},
        "about": about,
        # An example of making each type, for the ones whose example compiled.
        "examples": examples,
        # Each shared handle, like SharedKeyring, with its group and the built-in types that convert into it,
        # for the page's type explorer.
        "handles": {name: {"group": h["group"], "members": [m.split("::")[-1] for m in h["members"]]}
                    for name, h in API["handles"].items()},
    }
    args.out.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"{len(trials)} tries, {len(trials) - len(failed)} compiled, {runs} runs")


if __name__ == "__main__":
    main()
