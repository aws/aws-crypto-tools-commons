#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Turns a Stryker mutation report into results.json (see results.py).

Usage:
  stryker.py mutate-patterns <lines.json> [--glob 'modules/*/src/*.ts' ...]
      Prints one StrykerJS --mutate pattern per run of changed lines, for example
      modules/serialize/src/decode_body_header.ts:40-52. lines.json comes from
      `results.py changed-lines`. Prints nothing when no changed line matches a glob.
  stryker.py convert <mutation.json> --root <repo dir> --out <results.json>
                     --repository <owner/repo> --commit <sha> --language <language>
                     --library <library> --scope changed|full
                     [--lines <lines.json>] [--seconds <wall time>]
      With --lines, keeps only the mutants that start on a changed line.

StrykerJS and Stryker.NET both write the mutation-testing-report-schema JSON
(the "json" reporter), so this reads either.
StrykerJS names files relative to the directory that it ran in.
Stryker.NET names them by absolute path, so --root makes them relative.
Stryker.NET's --mutate takes no line ranges, so a .NET pull request run passes --lines instead.
"""

import argparse
import fnmatch
import json
import os
import sys

import results as results_file

# The schema's statuses. RuntimeError is a mutant that crashed the test run before any test could pass or fail.
# Stryker leaves it out of the mutation score like CompileError, so both are unviable here.
STATUS = {
    "Killed": "killed",
    "Timeout": "timed_out",
    "Survived": "survived",
    "NoCoverage": "not_covered",
    "CompileError": "unviable",
    "RuntimeError": "unviable",
    "Ignored": "not_sampled",
}


def mutate_patterns(lines, globs):
    """StrykerJS --mutate patterns, `file:start-end`, one per run of consecutive changed lines."""
    patterns = []
    for file, numbers in sorted(lines.items()):
        if not any(fnmatch.fnmatch(file, pattern) for pattern in globs):
            continue
        numbers = sorted(set(numbers))
        start = previous = numbers[0]
        for number in numbers[1:] + [None]:
            if number is not None and number == previous + 1:
                previous = number
                continue
            patterns.append("%s:%d-%d" % (file, start, previous))
            if number is not None:
                start = previous = number
    return patterns


def relative(path, root):
    path = path.replace("\\", "/")
    if os.path.isabs(path):
        path = os.path.relpath(path, root).replace("\\", "/")
    return path


def convert(report, root, changed=None):
    """The results.json mutant list for one Stryker report."""
    test_names = {test["id"]: test["name"]
                  for test_file in (report.get("testFiles") or {}).values() for test in test_file["tests"]}
    mutants = []
    for path, entry in sorted(report["files"].items()):
        file = relative(path, root)
        source = entry["source"].splitlines()
        for mutant in entry["mutants"]:
            if mutant["status"] not in STATUS:
                raise ValueError("%s: mutant %s has status %s, which the report should not contain after a run"
                                 % (file, mutant["id"], mutant["status"]))
            start, end = mutant["location"]["start"], mutant["location"]["end"]
            line = start["line"]
            if changed is not None and line not in changed.get(file, ()):
                continue
            source_line = source[line - 1] if line <= len(source) else ""
            description = mutant.get("description")
            if not description and "replacement" in mutant:
                # A mutant that spans lines, such as an emptied block, shows only its first line.
                if start["line"] == end["line"]:
                    original = source_line[start["column"] - 1:end["column"] - 1]
                else:
                    original = source_line[start["column"] - 1:].strip() + " ..."
                description = "%s -> %s" % (original.strip(), mutant["replacement"].strip())
            mutants.append({
                "id": "%s:%s" % (file, mutant["id"]),
                "file": file,
                "line": line,
                "kind": mutant["mutatorName"],
                "description": description or mutant["mutatorName"],
                # The schema has no enclosing function name.
                "function": "",
                "source_line": source_line.strip(),
                "status": STATUS[mutant["status"]],
                "killed_by": [test_names.get(test, test) for test in mutant.get("killedBy") or []],
                "static": bool(mutant.get("static")),
            })
    return mutants


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    patterns = commands.add_parser("mutate-patterns")
    patterns.add_argument("lines")
    patterns.add_argument("--glob", action="append", default=[])
    converted = commands.add_parser("convert")
    converted.add_argument("report")
    converted.add_argument("--root", required=True)
    converted.add_argument("--out", required=True)
    converted.add_argument("--repository", required=True)
    converted.add_argument("--commit", required=True)
    converted.add_argument("--language", required=True)
    converted.add_argument("--library", required=True)
    converted.add_argument("--scope", required=True, choices=("changed", "full"))
    converted.add_argument("--lines")
    converted.add_argument("--seconds", type=float)
    args = parser.parse_args()

    if args.command == "mutate-patterns":
        with open(args.lines) as f:
            lines = json.load(f)
        for pattern in mutate_patterns(lines, args.glob or ["*"]):
            print(pattern)
        return 0

    with open(args.report) as f:
        report = json.load(f)
    changed = None
    if args.lines:
        with open(args.lines) as f:
            changed = {file: set(numbers) for file, numbers in json.load(f).items()}
    mutants = convert(report, os.path.abspath(args.root), changed)
    performance = report.get("performance") or {}
    summary = {
        "repository": args.repository, "commit": args.commit,
        "language": args.language, "library": args.library,
        "tool": "stryker", "scope": args.scope,
        "mutants": len(mutants), "statuses": results_file.counts(mutants),
        "seconds": args.seconds if args.seconds is not None else sum(performance.values()) / 1000,
        "phases": {phase: milliseconds / 1000 for phase, milliseconds in performance.items()},
        "static": sum(1 for mutant in mutants if mutant["static"]),
        "framework": (report.get("framework") or {}).get("name", ""),
        "framework_version": (report.get("framework") or {}).get("version", ""),
    }
    with open(args.out, "w") as f:
        json.dump({"summary": summary, "mutants": mutants}, f, indent=1)
    rate = results_file.kill_rate(summary["statuses"])
    print("%d mutants, %s, kill rate %s" % (len(mutants), summary["statuses"],
                                             "%.0f%%" % (rate * 100) if rate is not None else "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
