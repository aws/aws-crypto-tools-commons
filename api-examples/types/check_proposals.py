#!/usr/bin/env python3
"""Check proposed signatures with the Rust compiler, and write them for the types page.

  check_proposals.py --input <proposals file> --rust-repo <aws-crypto-tools-rust checkout>

The api-signature-proposals skill writes the proposals file. Each Rust proposal lists its new setters
with their parameter types, plus Rust code for any new types they take. This script compiles every
held type against those setters, the way compile_rust_types.py tries the real ones. It records what
each type needs under the proposal, and which of today's calls would stop compiling.
A listed setter replaces the real setter with the same name. Setters it does not list stay as they are.
Other languages' proposals are not compiled: the kinds they list under as_is become as is.

It writes dashboard/api-examples/proposals.json, which git ignores. The types page shows it when it is there.

The proposals file looks like this:

  {"made_by": "who wrote the proposals",
   "options": {
     "esdk/encrypt.plaintext": {
       "why": "One sentence on what changes and why.",
       "rust": {"signature": "plaintext(impl Into<Plaintext>)",
                "code": "pub struct Plaintext; impl From<&[u8]> for Plaintext { ... }",
                "setters": {"plaintext": ["impl Into<Plaintext>"]}},
       "other": {"java": {"signature": "plaintext overloads: byte[], String", "as_is": ["bytes", "text"]}}},
     "mpl/HierarchicalKeyring.ttl": {"why": "No change: Duration says the unit."}}}

A setter whose name starts with set_ takes an Option. A setter with two parameter types takes a pair.
A parameter type may name a lifetime, like impl Into<Plaintext<'a>>.
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

import compile_rust_types as crt

OUT = crt.PAGE.parent / "proposals.json"
PATH_LIKE = re.compile(r"Path|path|FileInfo")


def setter_line(name, params):
    """A proposed setter as a free fn. Lifetimes its parameter types name, like 'a, become its own."""
    lifetimes = sorted(set(re.findall(r"'([a-z]\w*)", " ".join(params))) - {"static"})
    generics = "<" + ", ".join("'" + lt for lt in lifetimes) + ">" if lifetimes else ""
    args = ", ".join(f"{v}: {t}" for v, t in zip("xy", params))
    return f"pub fn {name}{generics}({args}) {{}}"


def fits(name, params, how):
    """True when a fix's way of passing the value matches the setter's shape."""
    if how == "pair":
        return len(params) == 2
    return len(params) == 1 and (how == "set") == name.startswith("set_")


def other_rows(rows, spec):
    """Another language's rows under a proposal: the listed kinds become as is, except paths.

    A changed row is called like the type the language takes as is today. Each row ends with its cost today.
    """
    kinds = spec.get("as_is", [])
    today = next((r for r in rows if r[1] == 0 and r[3] == "bytes"), None) or next((r for r in rows if r[1] == 0), None)
    rename = spec.get("rename") or []
    out = []
    for r in rows:
        if today and r[3] in kinds and r[1] != 0 and not PATH_LIKE.search(r[0]):
            code = today[2]
            if rename and (len(rename) < 3 or r[3] == rename[2]):
                code = code.replace(rename[0], rename[1])
            out.append([r[0], 0, code, r[3], r[1], True])
        else:
            out.append(r + [r[1], False])
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", required=True)
    parser.add_argument("--rust-repo", required=True)
    args = parser.parse_args()
    rust_repo = str(Path(args.rust_repo).resolve())
    proposals = json.loads(Path(args.input).read_text())
    options = proposals["options"]
    unknown = set(options) - {o[0] for o in crt.OPTIONS}
    if unknown:
        raise SystemExit(f"unknown options: {sorted(unknown)}")
    rust_specs = {key: spec["rust"] for key, spec in options.items() if spec.get("rust")}
    held, scratch = crt.prepare(rust_repo, "\n".join(s.get("code", "") for s in rust_specs.values()))

    # Today's setters first, then one module per proposal with its types and setters.
    trials, lines = crt.setter_trials(held)
    today_count = len(lines)
    modules = {}
    for i, (key, spec) in enumerate(sorted(rust_specs.items())):
        start = len(lines)
        lines.append(f"mod p{i} {{")
        lines += spec.get("code", "").splitlines()
        for name, params in spec["setters"].items():
            lines.append(setter_line(name, params))
        lines.append("}")
        modules[key] = (f"p{i}", start, len(lines))
    proposed_trials = []
    for key, (module, _, _) in modules.items():
        for label, expr, kind, fixes in held[key]:
            for cost, glue, how in fixes:
                for name, params in rust_specs[key]["setters"].items():
                    if fits(name, params, how):
                        proposed_trials.append((len(lines), key, label, kind, cost, how, glue, name))
                        lines.append(crt.trial(len(lines), "", expr, how, glue, f"{module}::{name}({glue})"))
    failed = scratch.errors(lines)
    scratch.remove()
    for key, (_, start, end) in modules.items():
        messages = [m for line, found in sorted(failed.items()) if start <= line < end for m in found]
        if messages:
            raise SystemExit(f"The Rust code for {key} does not compile:\n" + "\n".join(messages))

    today = crt.best_rows(trials, {n for n in failed if n < today_count})
    page = json.loads(crt.PAGE.read_text())
    setter_of = {o[0]: o[3] for o in crt.OPTIONS}
    before_of = {o[0]: (o[1][len(o[2]):] if o[2] else "") for o in crt.OPTIONS}
    compiled = {(key, label, how, glue, name) for n, key, label, _, _, how, glue, name in proposed_trials
                if n not in failed}
    result = {}
    for key, spec in options.items():
        languages = {}
        rust = rust_specs.get(key)
        if rust:
            replaced = set(rust["setters"])
            best, breaks = {}, {}
            # Each candidate is (cost, uses a proposed setter, call). A tie goes to today's setter.
            for n, (k, label, kind, cost, how, glue, call) in enumerate(trials):
                if k != key or n in failed:
                    continue
                real = f"set_{setter_of[key]}" if how == "set" else setter_of[key]
                if real not in replaced:
                    best.setdefault(label, []).append((cost, False, call))
                elif (key, label, how, glue, real) not in compiled:
                    breaks.setdefault(call, []).append(label)
            for _, k, label, kind, cost, how, glue, name in proposed_trials:
                if k == key and (key, label, how, glue, name) in compiled:
                    best.setdefault(label, []).append((cost, True, f"{before_of[key]}.{name}({glue})"))
            rows = []
            for label, cost_today, _, kind in today[key]:
                found = sorted(best.get(label, []))
                cost, new, call = found[0] if found else (None, False, "")
                rows.append([label, cost, call, kind, cost_today, new])
            rows.sort(key=lambda r: (r[1] is None, r[1] or 0, r[0]))
            languages["rust"] = {"signature": rust["signature"], "rows": rows,
                                 "breaks": [f"{call} with {', '.join(sorted(set(labels)))}"
                                            for call, labels in sorted(breaks.items())]}
        for lang, other in (spec.get("other") or {}).items():
            rows = ((page.get("others") or {}).get(key) or {}).get(lang) or []
            languages[lang] = {"signature": other["signature"], "rows": other_rows(rows, other)}
        result[key] = {"why": spec.get("why", ""), "languages": languages}

    commit = subprocess.run(["git", "-C", rust_repo, "rev-parse", "--short", "HEAD"], capture_output=True,
                            text=True, check=True).stdout.strip()
    tries = len(proposed_trials)
    # The input goes in too, so the file says where its proposals came from and can be checked again.
    out = {"made_by": proposals.get("made_by", ""),
           "checked": f"Proposals: Rust compiled on aws-crypto-tools-rust at {commit} ({tries:,} tries). "
                      "Other languages are not compiled.",
           "options": result,
           "input": proposals}
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"{tries} tries, {sum(1 for n, *_ in proposed_trials if n not in failed)} compiled; wrote {OUT}")


if __name__ == "__main__":
    main()
