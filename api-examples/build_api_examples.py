#!/usr/bin/env python3
"""Match one library's public API to the example blocks in its tests.

A language repo's discovery step writes surface.json: every public way to build
or call each API of one library. Tests mark pieces of a customer's call with
blocks of // comments. Each block starts with a marker line and ends with
// api-example: end, and the test code between them builds the whole object
and checks the result:

    // api-example: api=raw-aes-keyring way=key_name have="a string from your config"
    let key_name: String = app_config().key_name;
    // api-example: call
    let keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        // api-example: setter
        .key_name(key_name)
        ...
        .build()?;
    // api-example: end

Kinds of block:
  - frame (marker has `frame way=<constructor or method>`): the start and end of
    the call. Lines before `// api-example: call` are setup that every call needs
    (such as building a client). The head runs to `// api-example: options` or
    `// api-example: tail`, and the tail runs from `tail` to `end`. The option
    lines between `options` and `tail` are only there so the test builds; the
    dashboard uses the fragments instead. `one-of=a,b` says the call needs
    exactly one of those setter ways. One frame per API.
  - fragment (has a `// api-example: setter` line): one choice for one option.
    Lines before `call` are its setup, and the line after `setter` is its setter
    line. have= says what the customer starts from. `fails=<error kind>` means
    the call fails with that error. `default` marks the choice that the dashboard
    starts with and that other tests fill in; every required option and every
    one-of group has one. `alt` marks another way to write the same choice (Rust
    set_x(Some(..))), shown inside that choice and not as a choice of its own.
  - left-out (marker has `left-out`): the option is left out. With fails= the
    option is required; without it, optional. `way=a,b left-out` leaves out a
    whole one-of group, and `way=a,b together` sets more than one of it.
  - whole example (no setter line): for a constructor or method way that is not
    the frame's, such as Client::from_conf. The whole block is shown.

takes= optionally names the input type, and Java overloads must each be the
takes of some passing fragment.

This script writes api-examples.json for the dashboard. Each way gets the
dashboard row it belongs on, so that rows line up across languages:
  - construct: every constructor way (builder, new, from_conf, a Java factory, etc.).
  - an operation name from smithy-names.json, for a method way such as encrypt.
  - a Smithy member name from smithy-names.json, for a setter way whose option
    has the member's name or one of its aliases. Rust kms_key_id and
    set_kms_key_id, and every Java kmsKeyId overload, land on the row kmsKeyId.
  - extra:<option>, for a way that matches nothing in the model.

It fails when:
  - a way has no passing example (a frame, an ok fragment or a whole example),
  - an overload type (Java) is not the takes of any passing fragment,
  - an option has no left-out block, or one that fails and one that passes,
  - an API with ways has no frame or more than one,
  - a required option or one-of group has no default choice, or more than one,
  - an alt has no main choice with the same have, or two main choices share a have,
  - a one-of group has no failing left-out block or no failing together block,
  - a block names an api or way that surface.json does not have, or is malformed.
api-examples.json is written either way, so the dashboard can show the gaps.

Usage:
  build_api_examples.py --surface surface.json --src tests [more dirs...] \\
      --repo aws/aws-crypto-tools-rust --commit <sha> --out api-examples.json \\
      [--run-id <id> --run-attempt <n>] [--names smithy-names.json] \\
      [--template combos.template] [--combos combos.json]

--run-id and --run-attempt name the CI run whose tests ran the examples.
--template is the language's combos.template; the dashboard uses its new-test
section to write a new example test. --combos is combos.py's results for the
calls that CI built and ran.
"""

import argparse
import json
import re
import shlex
import sys
import textwrap
from pathlib import Path

MARKER = re.compile(r"^\s*//\s*api-example:(.*)$")
TAG = re.compile(r"^\s*//\s*api-example:\s*(call|setter|options|tail|end)\s*$")
KEYS = {"api", "way", "have", "takes", "fails", "one-of"}
FLAGS = {"frame", "default", "alt", "left-out", "together"}
NO_NAMES = {"members": [], "operations": [], "aliases": {}}


def option_key(name):
    """One spelling for names that differ only in case and underscores.

    kms_key_id, kmsKeyId and KmsKeyId give kmsKeyId; netV4_0_0_RetryPolicy and
    net_v4_0_0_retry_policy give netV400RetryPolicy.
    """
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s).lower()
    head, *rest = [p for p in s.split("_") if p]
    return head + "".join(p.capitalize() for p in rest)


def row_of(way, names):
    if way.get("kind") == "constructor":
        return "construct"
    key = option_key(way.get("option") or way["id"])
    if way.get("kind") == "method":
        found = {option_key(o): o for o in names["operations"]}.get(key)
    else:
        found = names["aliases"].get(key) or {option_key(m): m for m in names["members"]}.get(key)
    return found or "extra:" + key


def rows_of(ways, choices, names):
    rows = []
    # A client method such as encrypt is called, not constructed.
    if not names["operations"] or any(w["row"] == "construct" for w in ways):
        rows.append({"key": "construct", "label": "Construct", "kind": "construct"})
    rows += [{"key": o, "label": o, "kind": "operation"} for o in names["operations"]]
    rows += [{"key": m, "label": m, "kind": "member"} for m in names["members"]]
    for w in ways:
        if w["row"].startswith("extra:") and all(r["key"] != w["row"] for r in rows):
            rows.append({"key": w["row"], "label": w["row"][len("extra:"):], "kind": "extra"})
    for r in rows:
        r["haves"] = [c["have"] for c in choices if c["row"] == r["key"]]
    return rows


class Block:
    """One // api-example: block. lines are the block's lines without the marker and end lines."""

    def __init__(self, fields, flags, file, line):
        self.fields, self.flags, self.file, self.line = fields, flags, file, line
        self.api = fields.get("api")
        self.ways = [w for w in fields.get("way", "").split(",") if w]
        self.have, self.takes = fields.get("have"), fields.get("takes")
        self.error = fields.get("fails")
        self.one_of = [w for w in fields.get("one-of", "").split(",") if w]
        self.setup, self.head, self.tail, self.code = [], [], [], ""
        self.setter = None

    @property
    def kind(self):
        if "frame" in self.flags:
            return "frame"
        if "left-out" in self.flags:
            return "left-out"
        if "together" in self.flags:
            return "together"
        return "fragment" if self.setter is not None else "example"

    @property
    def where(self):
        return {"file": self.file, "line": self.line}


def dedent(lines):
    return textwrap.dedent("\n".join(lines)).split("\n") if lines else []


def split_block(block, body):
    """Fill in a block's parts from its body: (line number, text) pairs. Returns problems."""
    tags = [(i, TAG.match(text).group(1)) for i, (_, text) in enumerate(body) if TAG.match(text)]
    names = [t for _, t in tags]
    problems = [f"more than one // api-example: {t}" for t in sorted(set(names)) if names.count(t) > 1]
    pos = dict((t, i) for i, t in tags)
    if block.kind == "frame":
        if "setter" in pos:
            problems.append("a frame has no setter line")
    elif {"options", "tail"} & pos.keys():
        problems.append("only a frame has options and tail lines")
    if problems:
        return problems

    start = pos["call"] + 1 if "call" in pos else 0
    block.setup = dedent([t for _, t in body[:pos.get("call", 0)]])
    # Dedent the call's lines together so they keep their indent relative to the head.
    call = [(i, t) for i, (_, t) in enumerate(body) if i >= start and i not in pos.values()]
    texts = dedent([t for _, t in call])
    by_index = {i: t for (i, _), t in zip(call, texts)}
    if block.kind == "frame":
        head_end = min(pos.get("options", len(body)), pos.get("tail", len(body)))
        block.head = [by_index[i] for i in sorted(by_index) if i < head_end]
        block.tail = [by_index[i] for i in sorted(by_index) if i > pos["tail"]] if "tail" in pos else []
        if not block.head:
            problems.append("the frame has no head line")
    elif "setter" in pos:
        i = pos["setter"] + 1
        if i not in by_index or not by_index[i].strip():
            problems.append("no setter line after // api-example: setter")
        else:
            block.setter = by_index[i].rstrip()
    else:
        block.code = "\n".join(texts).strip("\n")
    return problems


def check_fields(block):
    problems = []
    kind, f = block.kind, block.fields
    if not block.api:
        problems.append("no api=")
    if not block.ways:
        problems.append("no way=")
    if len(block.ways) > 1 and kind not in ("left-out", "together"):
        problems.append("only left-out and together blocks name more than one way")
    if kind == "together" and (len(block.ways) < 2 or not block.error):
        problems.append("a together block names two or more ways and has fails=")
    if block.setter is not None and kind != "fragment":
        problems.append(f"a {kind} block has no setter line")
    if kind in ("fragment", "example") and not block.have:
        problems.append(f"a {kind} needs have=")
    if kind in ("frame", "left-out", "together") and "have" in f:
        problems.append(f"a {kind} has no have=")
    if block.one_of and kind != "frame":
        problems.append("only a frame has one-of=")
    if kind in ("frame", "example") and block.error:
        problems.append(f"a {kind} has no fails=")
    for flag in ("default", "alt"):
        if flag in block.flags and kind != "fragment":
            problems.append(f"only a fragment is {flag}")
    if {"default", "alt"} <= block.flags:
        problems.append("a fragment is default or alt, not both")
    if block.error and {"default", "alt"} & block.flags:
        problems.append("a default or alt fragment does not fail")
    if sum(x in block.flags for x in ("frame", "left-out", "together")) > 1:
        problems.append("frame, left-out and together do not go together")
    return problems


def read_blocks(path, shown_path):
    """Return (blocks, errors) for one source file. Each error is (line, message)."""
    try:
        data = path.read_bytes()
    except OSError:
        return [], []
    # Skip files without a marker before decoding, so binary test data is never read as text.
    if b"api-example:" not in data:
        return [], []
    lines = data.decode("utf-8", errors="replace").splitlines()
    blocks, errors = [], []
    i = 0
    while i < len(lines):
        m = MARKER.match(lines[i])
        if not m:
            i += 1
            continue
        if TAG.match(lines[i]):
            errors.append((i + 1, "a // api-example: tag outside a block"))
            i += 1
            continue
        marker_line = i + 1
        try:
            tokens = shlex.split(m.group(1))
        except ValueError:
            tokens = None
        end = i + 1
        while end < len(lines) and not (MARKER.match(lines[end]) and not TAG.match(lines[end])):
            if TAG.match(lines[end]) and TAG.match(lines[end]).group(1) == "end":
                break
            end += 1
        if end == len(lines) or not TAG.match(lines[end]):
            errors.append((marker_line, "no // api-example: end before the next marker or end of file"))
            i = end
            continue
        body = [(n + 1, lines[n]) for n in range(i + 1, end)]
        i = end + 1
        if tokens is None:
            errors.append((marker_line, "a quote is not closed"))
            continue
        fields, flags, bad = {}, set(), []
        for token in tokens:
            key, eq, value = token.partition("=")
            if eq and key in KEYS and key not in fields:
                fields[key] = value
            elif not eq and token in FLAGS and token not in flags:
                flags.add(token)
            else:
                bad.append(token)
        block = Block(fields, flags, shown_path, marker_line)
        problems = ["unknown or repeated fields: " + " ".join(bad)] if bad else []
        problems += split_block(block, body)
        if not problems:
            problems += check_fields(block)
        if problems:
            errors.append((marker_line, "; ".join(problems)))
            continue
        blocks.append(block)
    return blocks, errors


def scan(src_dirs, root):
    """Read every file under src_dirs. Paths in the output are relative to root."""
    blocks, errors = [], []
    for src in src_dirs:
        for path in sorted(Path(src).rglob("*")):
            if not path.is_file():
                continue
            try:
                shown = path.resolve().relative_to(root).as_posix()
            except ValueError:
                shown = path.as_posix()
            found, bad = read_blocks(path, shown)
            blocks += found
            errors += [(shown, line, msg) for line, msg in bad]
    return blocks, errors


def read_template(path):
    """The sections of a combos.template: {name: text}. Lines before the first @@ line are notes."""
    sections, name = {}, None
    for line in Path(path).read_text().splitlines():
        if line.startswith("@@ "):
            name = line[3:].strip()
            sections[name] = []
        elif name:
            sections[name].append(line)
    return {k: "\n".join(v).strip("\n") for k, v in sections.items()}


def render(text, values):
    """Fill {{name}} placeholders. A placeholder alone on a line takes a list of lines at its indent."""
    out = []
    for line in text.split("\n"):
        m = re.fullmatch(r"(\s*)\{\{(\w[\w-]*)\}\}", line)
        if m and isinstance(values.get(m.group(2)), list):
            out += [m.group(1) + v if v else "" for v in values[m.group(2)]]
        else:
            out.append(re.sub(r"\{\{(\w[\w-]*)\}\}", lambda x: str(values.get(x.group(1), x.group(0))), line))
    return "\n".join(out)


def build(surface, blocks, marker_errors, repo, commit, names, run=None, templates=None, combos=None):
    """Return (api-examples document, failures). Each failure is a dict with api, way and why.

    names is this library's part of smithy-names.json: {api id: entry}.
    run is {"id", "attempt"} of the CI run that ran the example tests, or None.
    templates is the language's combos.template sections, or None.
    combos is combos.py's results file, or None.
    """
    failures = []
    for file, line, msg in marker_errors:
        failures.append({"api": None, "way": None, "why": msg, "file": file, "line": line})

    def fail(api_id, way, why, block=None):
        failures.append({"api": api_id, "way": way, "why": why, **(block.where if block else {})})

    by_api = {}
    for b in blocks:
        by_api.setdefault(b.api, []).append(b)
    combo_results = {c["api"]: c for c in (combos or {}).get("apis", [])}

    apis = []
    known_apis = set()
    for api in surface.get("apis", []):
        api_id = api["id"]
        known_apis.add(api_id)
        api_names = names.get(api_id, NO_NAMES)
        ways = [dict(w) for w in api.get("ways", [])]
        ids = [w["id"] for w in ways]
        for dup in sorted({i for i in ids if ids.count(i) > 1}):
            fail(api_id, dup, "surface.json lists this way id twice")
        by_id = {w["id"]: w for w in ways}
        for w in ways:
            w["row"] = row_of(w, api_names)
        mine = by_api.get(api_id, [])
        for b in mine:
            for way in b.ways + b.one_of:
                if way not in by_id:
                    fail(api_id, way, "names a way that is not in surface.json", b)
        mine = [b for b in mine if all(w in by_id for w in b.ways + b.one_of)]

        def option(way_id):
            w = by_id[way_id]
            return w.get("option") or w["id"]

        def rows(way_ids):
            return list(dict.fromkeys(by_id[w]["row"] for w in way_ids))

        # The frame.
        frames = [b for b in mine if b.kind == "frame"]
        frame = None
        for b in frames:
            if by_id[b.ways[0]]["kind"] not in ("constructor", "method"):
                fail(api_id, b.ways[0], "a frame names a constructor or method way", b)
        if len(frames) > 1:
            for b in frames[1:]:
                fail(api_id, b.ways[0], "more than one frame for this API", b)
        if frames:
            f = frames[0]
            frame = {"way": f.ways[0], "setup": f.setup, "head": f.head, "tail": f.tail,
                     "one_of": rows(f.one_of), **f.where}
        elif ways:
            fail(api_id, None, "no frame")

        # Fragments and whole examples.
        choices, examples, alts = [], [], []
        for b in mine:
            way = by_id[b.ways[0]]
            if b.kind == "fragment":
                if way["kind"] != "setter":
                    fail(api_id, way["id"], "a setter line is for a setter way", b)
                    continue
                c = {"row": way["row"], "way": way["id"], "have": b.have, "setup": b.setup,
                     "setter": b.setter, "expect": "fails" if b.error else "ok", "error": b.error,
                     "default": "default" in b.flags, **b.where}
                if b.takes is not None:
                    c["takes"] = b.takes
                (alts if "alt" in b.flags else choices).append((option(way["id"]), c))
            elif b.kind == "example":
                if way["kind"] == "setter":
                    fail(api_id, way["id"], "an example of a setter way needs a // api-example: setter line", b)
                    continue
                e = {"way": way["id"], "row": way["row"], "have": b.have, "code": b.code, **b.where}
                if b.takes is not None:
                    e["takes"] = b.takes
                examples.append(e)
        seen = {}
        for opt, c in choices:
            if (opt, c["have"]) in seen:
                fail(api_id, c["way"], f"two choices with have={c['have']!r}")
            seen[(opt, c["have"])] = c
            c["alts"] = []
        for opt, a in alts:
            main = seen.get((opt, a["have"]))
            if main is None:
                fail(api_id, a["way"], f"an alt with have={a['have']!r}, which no main choice has")
                continue
            main["alts"].append({k: a[k] for k in ("way", "setup", "setter", "file", "line")})

        # Left-out blocks.
        group = frames[0].one_of if frames else []
        left_out, together = [], []
        for b in mine:
            if b.kind == "left-out":
                left_out.append({"ways": b.ways, "rows": rows(b.ways), "expect": "fails" if b.error else "ok",
                                 "error": b.error, **b.where})
            elif b.kind == "together":
                together.append({"ways": b.ways, "rows": rows(b.ways), "error": b.error, **b.where})
        if group:
            if not any(set(x["ways"]) == set(group) and x["expect"] == "fails" for x in left_out):
                fail(api_id, ",".join(group), "a one-of group needs a left-out block that fails")
            if not any(set(x["ways"]) == set(group) for x in together):
                fail(api_id, ",".join(group), "a one-of group needs a together block")

        # Coverage of every way.
        group_options = {option(w) for w in group}
        for w in ways:
            if w["kind"] in ("constructor", "method"):
                if not (frame and frame["way"] == w["id"]) and not any(e["way"] == w["id"] for e in examples):
                    fail(api_id, w["id"], "no frame or example")
                continue
            ok = [c for _, c in choices + alts if c["way"] == w["id"] and c["expect"] == "ok"]
            if not ok:
                fail(api_id, w["id"], "no fragment that works")
            takes = {c.get("takes") for c in ok}
            for overload in w.get("overloads", []):
                if ok and overload not in takes:
                    fail(api_id, w["id"], f"no fragment with takes={overload}")
        by_option = {}
        for w in ways:
            if w["kind"] == "setter":
                by_option.setdefault(option(w["id"]), []).append(w)
        for opt, opt_ways in by_option.items():
            ids_here = {w["id"] for w in opt_ways}
            kinds = {x["expect"] for x in left_out if len(x["ways"]) == 1 and x["ways"][0] in ids_here}
            first = opt_ways[0]["id"]
            if kinds == {"fails"}:
                required = True
            elif kinds == {"ok"}:
                required = False
            else:
                required = None
                fail(api_id, first, "a left-out block that fails and one that works, so required is unclear"
                     if kinds else "no left-out block, so required is unknown")
            for w in opt_ways:
                w["required"] = required
            defaults = [c for o, c in choices if o == opt and c["default"]]
            if len(defaults) > 1:
                fail(api_id, first, "more than one default choice")
            if required and not defaults:
                fail(api_id, first, "a required option needs a default choice")
            if required and opt in group_options:
                fail(api_id, first, "an option in a one-of group is not required on its own")
        if group and sum(c["default"] for o, c in choices if o in group_options) != 1:
            fail(api_id, ",".join(group), "a one-of group needs exactly one default choice")

        out_choices = [c for _, c in choices]
        out_api = {k: v for k, v in api.items() if k != "ways"}
        out_api.update({
            "ways": ways,
            "rows": rows_of(ways, out_choices, api_names),
            "frame": frame,
            "choices": out_choices,
            "left_out": [{k: v for k, v in x.items() if k != "ways"} for x in left_out],
            "together": [{k: v for k, v in x.items() if k != "ways"} for x in together],
            "examples": examples,
            "combos": combos_of(combo_results.get(api_id), ways),
        })
        apis.append(out_api)

    for api_id, found in sorted(by_api.items()):
        if api_id not in known_apis:
            for b in found:
                fail(api_id, ",".join(b.ways), "names an api that is not in surface.json", b)

    doc = {
        "schema": 4,
        "language": surface.get("language"),
        "library": surface.get("library"),
        "repo": repo,
        "commit": commit,
        "run": run,
        "templates": {k: templates[k] for k in ("new-test", "todo") if k in templates} if templates else None,
        "apis": apis,
        "uncovered": failures,
    }
    return doc, failures


def combos_of(result, ways):
    """combos.py's results for one API, with each choice keyed by its dashboard row and not its option."""
    if not result:
        return None
    row_of_option = {w.get("option") or w["id"]: w["row"] for w in ways}
    runs = []
    for c in result["combos"]:
        if c.get("outcome") is None:
            continue
        choices = {row_of_option.get(o, "extra:" + o): have for o, have in c["choices"].items()}
        runs.append({"choices": choices, "expect": c["expect"], "error": c.get("error"),
                     "outcome": c["outcome"], "name": c["name"]})
    return {"mode": result["mode"], "total": result["total"], "results": runs}


def describe(f):
    where = f" ({f['file']}:{f['line']})" if f.get("file") else ""
    name = f"{f['api']} {f['way'] or ''}".rstrip() if f.get("api") else "marker"
    return f"  {name}: {f['why']}{where}"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--surface", required=True, type=Path)
    p.add_argument("--src", required=True, nargs="+", type=Path,
                   help="test source directories to scan for markers")
    p.add_argument("--repo", required=True, help="owner/name of the language repo")
    p.add_argument("--commit", required=True)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--run-id", type=int)
    p.add_argument("--run-attempt", type=int, default=1)
    p.add_argument("--names", type=Path, default=Path(__file__).with_name("smithy-names.json"))
    p.add_argument("--template", type=Path)
    p.add_argument("--combos", type=Path)
    args = p.parse_args(argv)

    surface = json.loads(args.surface.read_text())
    if surface.get("schema") != 1:
        sys.exit(f"{args.surface}: schema must be 1, got {surface.get('schema')!r}")
    blocks, errors = scan(args.src, Path.cwd().resolve())
    names = json.loads(args.names.read_text())["libraries"].get(surface.get("library"), {})
    run = {"id": args.run_id, "attempt": args.run_attempt} if args.run_id else None
    templates = read_template(args.template) if args.template and args.template.exists() else None
    combos = json.loads(args.combos.read_text()) if args.combos and args.combos.exists() else None
    doc, failures = build(surface, blocks, errors, args.repo, args.commit, names, run, templates, combos)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2) + "\n")

    ways = sum(len(a["ways"]) for a in doc["apis"])
    ran = sum(len(a["combos"]["results"]) for a in doc["apis"] if a["combos"])
    print(f"{doc['library']} {doc['language']}: {len(doc['apis'])} apis, {ways} ways, "
          f"{len(blocks)} example blocks, {ran} calls built and run")
    if failures:
        print(f"{len(failures)} problems:")
        for f in failures:
            print(describe(f))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
