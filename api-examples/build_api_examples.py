#!/usr/bin/env python3
"""Match one library's public API to the snippets in its tests.

A language repo's discovery step writes surface.json: every public way to build
or call each API of one library. Tests mark the customer-facing part of a test
with these comments:

    // api-example: api=aws-kms-keyring way=kms_key_id takes=String kind=pass
    // snippet-start
    let keyring = AwsKmsKeyring::builder().kms_key_id(key_arn).build()?;
    // snippet-end

This script reads both and writes api-examples.json for the dashboard. Each way
gets the dashboard row it belongs on, so that rows line up across languages:
  - construct: every constructor way (builder, new, from_conf, a Java factory, etc.).
  - an operation name from smithy-names.json, for a method way such as encrypt.
  - a Smithy member name from smithy-names.json, for a setter way whose option
    has the member's name or one of its aliases. Rust kms_key_id and
    set_kms_key_id, and every Java kmsKeyId overload, land on the row kmsKeyId.
  - extra:<option>, for a way that matches nothing in the model.
Each API also lists its rows: construct, then operations and members in model
order (members that this language does not offer included), then extras.

It fails when:
  - a way has no kind=pass snippet,
  - an overload type (Java) is not the takes label of any pass snippet,
  - a setter's option has neither a kind=missing snippet (required) nor a
    kind=omitted snippet (optional), or has both,
  - a marker names an api or way that surface.json does not have, or is
    malformed.
api-examples.json is written either way, so the dashboard can show the gaps.

Usage:
  build_api_examples.py --surface surface.json --src tests [more dirs...] \
      --repo aws/aws-crypto-tools-rust --commit <sha> --out api-examples.json \
      [--names smithy-names.json]
"""

import argparse
import json
import re
import sys
import textwrap
from pathlib import Path

MARKER = re.compile(r"^\s*//\s*api-example:(.*)$")
START = re.compile(r"^\s*//\s*snippet-start\s*$")
END = re.compile(r"^\s*//\s*snippet-end\s*$")
KINDS = {"pass", "missing", "omitted", "reject"}
KEYS = {"api", "way", "takes", "kind"}
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


def rows_of(ways, names):
    rows = []
    # A client method such as encrypt is called, not constructed.
    if not names["operations"] or any(w["row"] == "construct" for w in ways):
        rows.append({"key": "construct", "label": "Construct", "kind": "construct"})
    rows += [{"key": o, "label": o, "kind": "operation"} for o in names["operations"]]
    rows += [{"key": m, "label": m, "kind": "member"} for m in names["members"]]
    for w in ways:
        if w["row"].startswith("extra:") and all(r["key"] != w["row"] for r in rows):
            rows.append({"key": w["row"], "label": w["row"][len("extra:"):], "kind": "extra"})
    return rows


class Snippet:
    def __init__(self, api, way, kind, takes, code, file, line):
        self.api, self.way, self.kind, self.takes = api, way, kind, takes
        self.code, self.file, self.line = code, file, line

    def to_json(self):
        out = {"kind": self.kind}
        if self.takes is not None:
            out["takes"] = self.takes
        out.update({"code": self.code, "file": self.file, "line": self.line})
        return out


def read_snippets(path, shown_path):
    """Return (snippets, errors) for one source file.

    Each error is (line, message). shown_path is the path written to the output.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return [], []
    # Skip files without a marker before decoding, so binary test data is never read as text.
    if b"api-example:" not in data:
        return [], []
    lines = data.decode("utf-8", errors="replace").splitlines()
    snippets, errors = [], []
    i = 0
    while i < len(lines):
        m = MARKER.match(lines[i])
        if not m:
            i += 1
            continue
        marker_line = i + 1
        fields, bad = {}, []
        for token in m.group(1).split():
            key, eq, value = token.partition("=")
            if not eq or key not in KEYS or key in fields:
                bad.append(token)
            else:
                fields[key] = value
        i += 1
        if not i < len(lines) or not START.match(lines[i]):
            errors.append((marker_line, "no // snippet-start on the line after the marker"))
            continue
        start = i + 1
        end = start
        while end < len(lines) and not END.match(lines[end]) and not MARKER.match(lines[end]):
            end += 1
        if end == len(lines) or not END.match(lines[end]):
            errors.append((marker_line, "no // snippet-end before the next marker or end of file"))
            i = end
            continue
        i = end + 1
        problems = []
        if bad:
            problems.append("unknown or repeated fields: " + " ".join(bad))
        for key in ("api", "way", "kind"):
            if not fields.get(key):
                problems.append(f"no {key}=")
        if fields.get("kind") and fields["kind"] not in KINDS:
            problems.append(f"kind={fields['kind']} is not one of {', '.join(sorted(KINDS))}")
        if fields.get("kind") == "pass" and not fields.get("takes"):
            problems.append("kind=pass needs takes=")
        if start == end:
            problems.append("the snippet is empty")
        if problems:
            errors.append((marker_line, "; ".join(problems)))
            continue
        code = textwrap.dedent("\n".join(lines[start:end])).strip("\n")
        snippets.append(Snippet(fields["api"], fields["way"], fields["kind"],
                                fields.get("takes"), code, shown_path, start + 1))
    return snippets, errors


def scan(src_dirs, root):
    """Read every file under src_dirs. Paths in the output are relative to root."""
    snippets, errors = [], []
    for src in src_dirs:
        for path in sorted(Path(src).rglob("*")):
            if not path.is_file():
                continue
            try:
                shown = path.resolve().relative_to(root).as_posix()
            except ValueError:
                shown = path.as_posix()
            found, bad = read_snippets(path, shown)
            snippets += found
            errors += [(shown, line, msg) for line, msg in bad]
    return snippets, errors


def build(surface, snippets, marker_errors, repo, commit, names):
    """Return (api-examples document, failures). Each failure is a dict with api, way and why.

    names is this library's part of smithy-names.json: {api id: entry}.
    """
    failures = []
    for file, line, msg in marker_errors:
        failures.append({"api": None, "way": None, "why": msg, "file": file, "line": line})

    by_way = {}
    for s in snippets:
        by_way.setdefault((s.api, s.way), []).append(s)

    known = set()
    apis = []
    for api in surface.get("apis", []):
        ways = api.get("ways", [])
        api_names = names.get(api["id"], NO_NAMES)
        ids = [w["id"] for w in ways]
        for dup in sorted({i for i in ids if ids.count(i) > 1}):
            failures.append({"api": api["id"], "way": dup, "why": "surface.json lists this way id twice"})
        known.update((api["id"], i) for i in ids)

        # Rust x() and set_x() share one option, so a missing or omitted
        # snippet on either one says whether the option is required.
        left_out = {}
        for w in ways:
            if w.get("kind") == "setter":
                key = w.get("option") or w["id"]
                kinds = left_out.setdefault(key, set())
                kinds.update(s.kind for s in by_way.get((api["id"], w["id"]), [])
                             if s.kind in ("missing", "omitted"))

        out_ways = []
        for w in ways:
            examples = by_way.get((api["id"], w["id"]), [])
            out = dict(w)
            out["row"] = row_of(w, api_names)
            out["examples"] = [s.to_json() for s in examples]
            takes = {s.takes for s in examples if s.kind == "pass"}
            if not takes:
                failures.append({"api": api["id"], "way": w["id"], "why": "no pass snippet"})
            for overload in w.get("overloads", []):
                if takes and overload not in takes:
                    failures.append({"api": api["id"], "way": w["id"],
                                     "why": f"no pass snippet with takes={overload}"})
            if w.get("kind") == "setter":
                kinds = left_out[w.get("option") or w["id"]]
                if kinds == {"missing"}:
                    out["required"] = True
                elif kinds == {"omitted"}:
                    out["required"] = False
                elif kinds:
                    failures.append({"api": api["id"], "way": w["id"],
                                     "why": "both missing and omitted snippets, so required is unclear"})
                else:
                    failures.append({"api": api["id"], "way": w["id"],
                                     "why": "no missing or omitted snippet, so required is unknown"})
            out_ways.append(out)
        out_api = {k: v for k, v in api.items() if k != "ways"}
        out_api["ways"] = out_ways
        out_api["rows"] = rows_of(out_ways, api_names)
        apis.append(out_api)

    for (api_id, way_id), found in sorted(by_way.items()):
        if (api_id, way_id) not in known:
            for s in found:
                failures.append({"api": api_id, "way": way_id,
                                 "why": "marker names an api and way not in surface.json",
                                 "file": s.file, "line": s.line})

    doc = {
        "schema": 2,
        "language": surface.get("language"),
        "library": surface.get("library"),
        "repo": repo,
        "commit": commit,
        "apis": apis,
        "uncovered": failures,
    }
    return doc, failures


def describe(f):
    where = f" ({f['file']}:{f['line']})" if f.get("file") else ""
    name = f"{f['api']} {f['way']}" if f.get("api") else "marker"
    return f"  {name}: {f['why']}{where}"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--surface", required=True, type=Path)
    p.add_argument("--src", required=True, nargs="+", type=Path,
                   help="test source directories to scan for markers")
    p.add_argument("--repo", required=True, help="owner/name of the language repo")
    p.add_argument("--commit", required=True)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--names", type=Path, default=Path(__file__).with_name("smithy-names.json"))
    args = p.parse_args(argv)

    surface = json.loads(args.surface.read_text())
    if surface.get("schema") != 1:
        sys.exit(f"{args.surface}: schema must be 1, got {surface.get('schema')!r}")
    snippets, errors = scan(args.src, Path.cwd().resolve())
    names = json.loads(args.names.read_text())["libraries"].get(surface.get("library"), {})
    doc, failures = build(surface, snippets, errors, args.repo, args.commit, names)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2) + "\n")

    ways = sum(len(a["ways"]) for a in doc["apis"])
    print(f"{doc['library']} {doc['language']}: {len(doc['apis'])} apis, {ways} ways, "
          f"{len(snippets)} snippets")
    if failures:
        print(f"{len(failures)} problems:")
        for f in failures:
            print(describe(f))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
