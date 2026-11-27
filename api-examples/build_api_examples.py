#!/usr/bin/env python3
"""Write api-examples.json for a released library, from read_shipped.py's surface.json.

read_shipped.py lists every public way to build or call each API of one released
library. This script gives each way the row it belongs on, so that rows line up
across languages:
  - construct: every constructor way (builder, new, from_conf, a Java factory, etc.).
  - an operation name from smithy-names.json, for a method way such as encrypt.
  - a Smithy member name from smithy-names.json, for a setter way whose option
    has the member's name or one of its aliases. Every Java kmsKeyId overload and
    Go KmsKeyId field land on the row kmsKeyId.
  - extra:<option>, for a way that matches nothing in the model.
Each type that a setter takes also becomes a choice, named by type-phrases.json.
api-examples/types/other_languages.py reads the ways and their rows.

Usage:
  build_api_examples.py --surface surface.json --repo aws/aws-crypto-tools-commons \\
      --commit <sha> --out api-examples.json [--run-id <id> --run-attempt <n>] [--names smithy-names.json]

--run-id and --run-attempt name the CI run that read the released library.
"""

import argparse
import json
import re
import sys
from pathlib import Path

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


def short_type(text):
    """A type without package names or pointer and nullable marks.

    java.util.List<java.lang.String> gives List<String>, *kms.Client gives
    Client, and Int64? gives Int64.
    """
    text = re.sub(r"\b(?:[A-Za-z_]\w*\.)+(?=[A-Za-z_])", "", text.strip())
    return text.lstrip("*").rstrip("?")


def have_of(type_text, phrases):
    """What a customer has, for one parameter type, from type-phrases.json. A type it does not list is its own name."""
    t = short_type(type_text)
    return next((p for p, types in phrases.items() if t in types), t)


def build_shipped(surface, names, phrases, repo, commit, run=None):
    """The api-examples document for a library as it ships, from read_shipped.py's surface.json.

    It has no tests to match, so each type that a setter way takes becomes a
    choice with expect "shipped", and each constructor or method way becomes a
    whole example that shows its signature.
    """
    apis = []
    for api in surface.get("apis", []):
        api_names = names.get(api["id"], NO_NAMES)
        ways = [dict(w, required=None) for w in api.get("ways", [])]
        choices, examples = [], []
        for w in ways:
            w["row"] = row_of(w, api_names)
            if w["kind"] != "setter":
                examples.append({"way": w["id"], "row": w["row"], "have": "", "code": w["signature"]})
                continue
            for take in w.get("takes", []):
                have = have_of(take["type"], phrases)
                same = next((c for c in choices if c["row"] == w["row"] and c["have"] == have), None)
                if same:
                    if take["type"] not in same["takes"].split(" | "):
                        same["takes"] += " | " + take["type"]
                    continue
                choices.append({"row": w["row"], "way": w["id"], "have": have, "setup": [], "setter": take["signature"],
                                "expect": "shipped", "error": None, "default": False, "takes": take["type"], "alts": []})
        out_api = {k: v for k, v in api.items() if k != "ways"}
        out_api.update({"ways": ways, "rows": rows_of(ways, choices, api_names), "frame": None, "choices": choices,
                        "left_out": [], "together": [], "examples": examples, "combos": None, "shipped": True})
        apis.append(out_api)
    return {"schema": 4, "language": surface.get("language"), "library": surface.get("library"),
            "shipped": surface.get("shipped"), "repo": repo, "commit": commit, "run": run,
            "templates": None, "apis": apis, "uncovered": []}


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


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--surface", required=True, type=Path)
    p.add_argument("--phrases", type=Path, default=Path(__file__).with_name("type-phrases.json"))
    p.add_argument("--repo", required=True, help="owner/name of the repo whose CI read the library")
    p.add_argument("--commit", required=True)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--run-id", type=int)
    p.add_argument("--run-attempt", type=int, default=1)
    p.add_argument("--names", type=Path, default=Path(__file__).with_name("smithy-names.json"))
    args = p.parse_args(argv)

    surface = json.loads(args.surface.read_text())
    if surface.get("schema") != 1:
        sys.exit(f"{args.surface}: schema must be 1, got {surface.get('schema')!r}")
    names = json.loads(args.names.read_text())["libraries"].get(surface.get("library"), {})
    run = {"id": args.run_id, "attempt": args.run_attempt} if args.run_id else None
    phrases = json.loads(args.phrases.read_text())["phrases"]
    doc = build_shipped(surface, names, phrases, args.repo, args.commit, run)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"{doc['library']} {doc['language']} shipped {doc['shipped']['package']} {doc['shipped']['version']}: "
          f"{len(doc['apis'])} apis, {sum(len(a['choices']) for a in doc['apis'])} choices")
    return 0


if __name__ == "__main__":
    sys.exit(main())
