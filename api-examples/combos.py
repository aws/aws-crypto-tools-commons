#!/usr/bin/env python3
"""Write a test for every call that the API examples dashboard can make, and record how they ran.

The dashboard builds a call from an API's frame plus one choice per option:
leave it out, or one of that option's fragments (see build_api_examples.py).
`generate` reads the examples and surface.json and writes one test per such call,
from the language's combos.template, so CI builds and runs every call that the dashboard can show:

  - When no fragment or left-out option fails, the call must work.
  - When exactly one part fails, the call must fail with that part's error kind.
    A part is a fragment with fails=, a required option that is left out, or a
    one-of group with none or more than one of its ways set.
  - When two or more parts fail, the call must just fail.

An API with more than --cap calls gets a pairwise sample instead: every pair of
choices for two options is in some call. The sample always holds the call that
the dashboard starts with (each option's default choice, others left out).
combos.json records which it did.

`record` reads the test results and writes each call's outcome into combos.json.

Usage:
  combos.py generate --surface surface.json --src tests/api_examples --template tests/api_examples/combos.template \\
      --out tests/api_example_combos.rs --manifest combos.json [--cap 200]
  combos.py record --manifest combos.json (--libtest cargo-test.log | --junit build/test-results)
"""

import argparse
import itertools
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import build_api_examples as builder

LEFT_OUT = None


class Api:
    """option_of maps each way id to its option, so Rust x and set_x are one option."""

    def __init__(self, frame, blocks, option_of):
        self.id = frame.api
        self.frame = frame
        self.group = [option_of.get(w, w) for w in frame.one_of]
        fragments = [b for b in blocks if b.kind == "fragment" and "alt" not in b.flags]
        left_out = {option_of.get(b.ways[0], b.ways[0]): b for b in blocks
                    if b.kind == "left-out" and len(b.ways) == 1}
        group_ways = set(frame.one_of)
        self.group_left_out = next((b for b in blocks if b.kind == "left-out" and set(b.ways) == group_ways), None)
        self.together = next((b for b in blocks if b.kind == "together" and set(b.ways) == group_ways), None)
        # Options in the order that the source first mentions them.
        mentioned = sorted(fragments + [b for b in blocks if b.kind == "left-out" and len(b.ways) == 1],
                           key=lambda b: (b.file, b.line))
        self.options = list(dict.fromkeys(option_of.get(b.ways[0], b.ways[0]) for b in mentioned))
        self.choices = {}
        for opt in self.options:
            mine = [b for b in fragments if option_of.get(b.ways[0], b.ways[0]) == opt]
            # An option with no left-out block has no known result when it is left out, so it is always set.
            self.choices[opt] = ([LEFT_OUT] if opt in left_out else []) + mine
        self.left_out = left_out

    def start(self):
        """The call that the dashboard starts with: each option's default, or left out."""
        out = []
        for opt in self.options:
            values = self.choices[opt]
            default = next((i for i, b in enumerate(values) if b is not LEFT_OUT and "default" in b.flags), None)
            out.append(default if default is not None else 0)
        return tuple(out)

    def total(self):
        n = 1
        for opt in self.options:
            n *= len(self.choices[opt])
        return n

    def expect(self, picks):
        """(expect, error) for one call: picks[i] indexes self.choices[self.options[i]]."""
        errors = []
        chosen = {opt: self.choices[opt][i] for opt, i in zip(self.options, picks)}
        for opt, b in chosen.items():
            if b is LEFT_OUT:
                lo = self.left_out[opt]
                if lo.error and opt not in self.group:
                    errors.append(lo.error)
            elif b.error:
                errors.append(b.error)
        if self.group:
            n = sum(chosen.get(w, LEFT_OUT) is not LEFT_OUT for w in self.group)
            if n == 0:
                errors.append(self.group_left_out.error if self.group_left_out else None)
            elif n > 1:
                errors.append(self.together.error if self.together else None)
        if not errors:
            return "ok", None
        return "fails", errors[0] if len(errors) == 1 else None

    def code(self, picks):
        chosen = [self.choices[opt][i] for opt, i in zip(self.options, picks)]
        picked = [b for b in chosen if b is not LEFT_OUT]
        lines = list(self.frame.setup)
        for b in picked:
            lines += b.setup
        lines += self.frame.head
        lines += [b.setter for b in picked]
        lines += self.frame.tail
        return lines


def pair(i, a, j, b):
    return (i, a, j, b) if i < j else (j, b, i, a)


def pairwise(sizes, seed):
    """Rows (tuples of value indexes) that hold every pair of values of two parameters."""
    params = range(len(sizes))
    uncovered = {(i, a, j, b) for i, j in itertools.combinations(params, 2)
                 for a in range(sizes[i]) for b in range(sizes[j])}

    def cover(row):
        for i, j in itertools.combinations(params, 2):
            uncovered.discard((i, row[i], j, row[j]))

    rows = [seed]
    cover(seed)
    while uncovered:
        i, a, j, b = min(uncovered)
        row = {i: a, j: b}
        for k in params:
            if k in row:
                continue
            # The value that covers the most pairs that are still uncovered.
            gain = [sum(pair(k, v, m, row[m]) in uncovered for m in row) for v in range(sizes[k])]
            row[k] = gain.index(max(gain))
        row = tuple(row[k] for k in params)
        rows.append(row)
        cover(row)
    return rows


def generate(args):
    blocks, errors = builder.scan(args.src, Path.cwd().resolve())
    if errors:
        for file, line, msg in errors:
            print(f"{file}:{line}: {msg}", file=sys.stderr)
        return 1
    by_api = {}
    for b in blocks:
        by_api.setdefault(b.api, []).append(b)
    surface = json.loads(args.surface.read_text())
    option_of = {a["id"]: {w["id"]: w.get("option") or w["id"] for w in a["ways"]} for a in surface["apis"]}
    apis = [Api(f, by_api[f.api], option_of.get(f.api, {})) for f in blocks if f.kind == "frame"]
    manifest = {"schema": 1, "apis": []}
    tests = []
    template = builder.read_template(args.template) if apis else None
    for api in apis:
        sizes = [len(api.choices[o]) for o in api.options]
        total = api.total()
        if total <= args.cap:
            mode, rows = "all", list(itertools.product(*[range(s) for s in sizes]))
        else:
            mode, rows = "pairwise", pairwise(sizes, api.start())
        entry = {"api": api.id, "mode": mode, "total": total, "combos": []}
        for n, picks in enumerate(rows, 1):
            name = f"{api.id.replace('-', '_')}_{n:03}"
            expect, error = api.expect(picks)
            choices = {opt: (None if api.choices[opt][i] is LEFT_OUT else api.choices[opt][i].have)
                       for opt, i in zip(api.options, picks)}
            entry["combos"].append({"name": name, "choices": choices, "expect": expect, "error": error})
            if expect == "ok":
                check = template["ok"]
            elif error:
                check = builder.render(template["fails-with"], {"error": error})
            else:
                check = template["fails"]
            tests.append(builder.render(template["test"], {
                "name": name, "code": api.code(picks), "check": check.split("\n")}))
        manifest["apis"].append(entry)
        print(f"{api.id}: {len(rows)} calls ({mode}, {total} possible)")
    if apis:
        body = builder.render(template["file"], {"tests": "\n\n".join(tests).split("\n")})
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(body + "\n")
    else:
        print("no frames, so no calls to write")
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n")
    return 0


LIBTEST = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)")


def outcomes_from_libtest(path):
    out = {}
    for line in Path(path).read_text(errors="replace").splitlines():
        m = LIBTEST.match(line)
        if m:
            out[m.group(1)] = {"ok": "pass", "FAILED": "fail", "ignored": None}[m.group(2)]
    return out


def outcomes_from_junit(directory):
    out = {}
    for path in sorted(Path(directory).rglob("*.xml")):
        for case in ET.parse(path).getroot().iter("testcase"):
            name = case.get("name", "").removesuffix("()")
            failed = case.find("failure") is not None or case.find("error") is not None
            out[name] = None if case.find("skipped") is not None else ("fail" if failed else "pass")
    return out


def record(args):
    manifest = json.loads(args.manifest.read_text())
    outcomes = outcomes_from_libtest(args.libtest) if args.libtest else outcomes_from_junit(args.junit)
    missing = []
    for api in manifest["apis"]:
        for c in api["combos"]:
            c["outcome"] = outcomes.get(c["name"])
            if c["outcome"] is None:
                missing.append(c["name"])
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n")
    ran = sum(c["outcome"] is not None for a in manifest["apis"] for c in a["combos"])
    print(f"recorded {ran} calls")
    if missing:
        print(f"{len(missing)} calls have no result: {', '.join(missing[:10])}", file=sys.stderr)
        return 1
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--surface", required=True, type=Path)
    g.add_argument("--src", required=True, nargs="+", type=Path)
    g.add_argument("--template", required=True, type=Path)
    g.add_argument("--out", required=True, type=Path)
    g.add_argument("--manifest", required=True, type=Path)
    g.add_argument("--cap", type=int, default=200)
    r = sub.add_parser("record")
    r.add_argument("--manifest", required=True, type=Path)
    source = r.add_mutually_exclusive_group(required=True)
    source.add_argument("--libtest", type=Path, help="the output of cargo test")
    source.add_argument("--junit", type=Path, help="a directory of JUnit XML reports")
    args = p.parse_args(argv)
    return generate(args) if args.command == "generate" else record(args)


if __name__ == "__main__":
    sys.exit(main())
