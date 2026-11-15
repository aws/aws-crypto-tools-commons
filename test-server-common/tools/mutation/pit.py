#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Turns a PIT mutation report into results.json (see results.py).

Usage:
  pit.py target-classes <lines.json> --source-root src/main/java [--source-root ...]
      Prints PIT's targetClasses for the Java files that lines.json names, for example
      com.amazonaws.encryptionsdk.AwsCrypto,com.amazonaws.encryptionsdk.AwsCrypto$*
      lines.json comes from `results.py changed-lines`. Prints nothing when no changed file is
      under a source root.
  pit.py convert <mutations.xml> --source-root <dir> [--source-root ...] --out <results.json>
                 --repository <owner/repo> --commit <sha> --language <language>
                 --library <library> --scope changed|full
                 [--lines <lines.json>] [--seconds <wall time>]
      With --lines, keeps only the mutants on a changed line.

PIT mutates whole classes, so a pull request run mutates every class it touches and
--lines then drops the mutants on lines that the pull request did not change.
Source roots are relative to the repository root, which is the working directory.
"""

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ElementTree

import results as results_file

# PIT counts a mutant that ran out of memory or crashed the test JVM as detected, so they are killed here.
STATUS = {
    "KILLED": "killed",
    "MEMORY_ERROR": "killed",
    "RUN_ERROR": "killed",
    "TIMED_OUT": "timed_out",
    "SURVIVED": "survived",
    "NO_COVERAGE": "not_covered",
    "NON_VIABLE": "unviable",
}


def target_classes(lines, roots):
    classes = []
    for file in sorted(lines):
        if not file.endswith(".java"):
            continue
        for root in roots:
            prefix = root.rstrip("/") + "/"
            if file.startswith(prefix):
                name = file[len(prefix):-len(".java")].replace("/", ".")
                classes += [name, name + "$*"]
                break
    return classes


def source_file(mutated_class, file_name, roots):
    """The repository path of the file that holds `mutated_class`."""
    package = mutated_class.split("$")[0].rpartition(".")[0]
    for root in roots:
        path = os.path.join(root, package.replace(".", "/"), file_name)
        if os.path.exists(path):
            return path.replace("\\", "/")
    raise ValueError("%s: no %s under %s" % (mutated_class, file_name, ", ".join(roots)))


def tests(mutation, plural, singular):
    """The test names in <killingTests> (a full mutation matrix) or <killingTest>."""
    text = mutation.findtext(plural)
    if text is None:
        text = mutation.findtext(singular)
    return [name for name in (text or "").split("|") if name]


def convert(report, roots, changed=None):
    sources, mutants = {}, []
    for mutation in report.getroot().iter("mutation"):
        status = mutation.get("status")
        if status not in STATUS:
            raise ValueError("a mutant has status %s, which means the PIT run did not finish" % status)
        file = source_file(mutation.findtext("mutatedClass"), mutation.findtext("sourceFile"), roots)
        line = int(mutation.findtext("lineNumber"))
        if changed is not None and line not in changed.get(file, ()):
            continue
        if file not in sources:
            with open(file, encoding="utf-8") as f:
                sources[file] = f.read().splitlines()
        source = sources[file]
        mutator = mutation.findtext("mutator")
        mutants.append({
            "id": "%s:%d:%s:%s" % (file, line, mutator.rpartition(".")[2], mutation.findtext("indexes/index") or ""),
            "file": file,
            "line": line,
            "kind": mutator.rpartition(".")[2],
            "description": mutation.findtext("description") or mutator,
            "function": mutation.findtext("mutatedMethod") or "",
            "source_line": source[line - 1].strip() if line <= len(source) else "",
            "status": STATUS[status],
            "killed_by": tests(mutation, "killingTests", "killingTest"),
        })
    return mutants


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    classes = commands.add_parser("target-classes")
    classes.add_argument("lines")
    classes.add_argument("--source-root", action="append", required=True)
    converted = commands.add_parser("convert")
    converted.add_argument("report")
    converted.add_argument("--source-root", action="append", required=True)
    converted.add_argument("--out", required=True)
    converted.add_argument("--repository", required=True)
    converted.add_argument("--commit", required=True)
    converted.add_argument("--language", required=True)
    converted.add_argument("--library", required=True)
    converted.add_argument("--scope", required=True, choices=("changed", "full"))
    converted.add_argument("--lines")
    converted.add_argument("--seconds", type=float)
    args = parser.parse_args()

    if args.command == "target-classes":
        with open(args.lines) as f:
            names = target_classes(json.load(f), args.source_root)
        if names:
            print(",".join(names))
        return 0

    changed = None
    if args.lines:
        with open(args.lines) as f:
            changed = {file: set(numbers) for file, numbers in json.load(f).items()}
    if os.path.exists(args.report):
        mutants = convert(ElementTree.parse(args.report), args.source_root, changed)
    else:
        # PIT writes no report when the pull request changes no source file.
        mutants = []
    summary = {
        "repository": args.repository, "commit": args.commit,
        "language": args.language, "library": args.library,
        "tool": "pit", "scope": args.scope,
        "mutants": len(mutants), "statuses": results_file.counts(mutants),
        "seconds": args.seconds or 0, "phases": {},
    }
    with open(args.out, "w") as f:
        json.dump({"summary": summary, "mutants": mutants}, f, indent=1)
    rate = results_file.kill_rate(summary["statuses"])
    print("%d mutants, %s, kill rate %s" % (len(mutants), summary["statuses"],
                                             "%.0f%%" % (rate * 100) if rate is not None else "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
