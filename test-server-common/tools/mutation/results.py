#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The mutation results file that every language writes, and the check that blocks a pull request.

Usage:
  results.py changed-lines --repo <dir> --base <git ref> --out <json> [--glob '*.java' ...]
      Writes {file: [line, ...]} for the lines added or changed since the branch left <base>.
  results.py check <results.json> [--fail]
      Prints the counts and every survivor and not-covered mutant (also to $GITHUB_STEP_SUMMARY).
      With --fail, exits 1 if a mutant survived or sits on a line that no test runs.

results.json, written by mutate.py for Rust and by the <tool>.py converters for the other languages:
  {"summary": {
     "repository": "aws/aws-encryption-sdk-java", "commit": "<sha>",
     "language": "java", "library": "esdk",      # esdk, mpl, dbesdk or prim
     "tool": "pit",                             # mutate.py, pit, stryker, ...
     "scope": "changed" or "full",              # changed: only mutants on the pull request's changed lines
     "mutants": <count>, "statuses": {"<status>": <count>},
     "seconds": <wall time>, "phases": {"<step>": <seconds>}, ...},
   "mutants": [{"id", "file", "line", "kind", "description", "function", "source_line",
                "status", "killed_by"}, ...]}
"file" is relative to the repository root.
A status is one of:
  killed       a test failed with the mutant on
  timed_out    a test hung with the mutant on; counts as killed
  survived     every test that runs the line passed
  not_covered  no test runs the line
  unviable     the mutant does not compile; not counted
  not_sampled  left out of this run (--sample); not counted
"""

import argparse
import collections
import fnmatch
import json
import os
import re
import subprocess
import sys

STATUSES = ("killed", "timed_out", "survived", "not_covered", "unviable", "not_sampled")
BLOCKING = ("survived", "not_covered")


def changed_lines(repo, base, globs=("*",)):
    """{file: [line, ...]} for lines added or changed since this branch left `base`."""
    fork = subprocess.run(["git", "-C", repo, "merge-base", base, "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()
    diff = subprocess.run(["git", "-C", repo, "diff", "-U0", fork], check=True,
                          capture_output=True, text=True).stdout
    lines, file = collections.defaultdict(list), None
    for text in diff.splitlines():
        if text.startswith("+++ "):
            file = text[6:] if text.startswith("+++ b/") else None
            if file and not any(fnmatch.fnmatch(file, pattern) for pattern in globs):
                file = None
        elif text.startswith("@@") and file:
            start, _, count = re.match(r"@@ -\S+ \+(\d+)(,(\d+))? @@", text).groups()
            lines[file].extend(range(int(start), int(start) + (int(count) if count is not None else 1)))
    return dict(lines)


def counts(mutants):
    return dict(collections.Counter(mutant["status"] for mutant in mutants if mutant["status"] != "not_sampled"))


def kill_rate(statuses):
    killed = statuses.get("killed", 0) + statuses.get("timed_out", 0)
    tested = killed + statuses.get("survived", 0)
    return killed / tested if tested else None


def check(path, fail):
    with open(path) as f:
        data = json.load(f)
    summary, mutants = data["summary"], data["mutants"]
    statuses = counts(mutants)
    rate = kill_rate(statuses)
    lines = ["### Mutation testing: %s %s (%s)" % (summary.get("library", ""), summary.get("language", ""),
                                                    "changed lines" if summary.get("scope") == "changed" else "full library"),
             "",
             "%d mutants: %s. Kill rate %s." % (
                 sum(statuses.values()), ", ".join("%d %s" % (statuses[s], s.replace("_", " ")) for s in STATUSES if statuses.get(s)) or "none",
                 "%.0f%%" % (rate * 100) if rate is not None else "-")]
    blocking = [mutant for mutant in mutants if mutant["status"] in BLOCKING]
    if blocking:
        lines += ["", "| status | line | mutation | code |", "| --- | --- | --- | --- |"]
        for mutant in sorted(blocking, key=lambda m: (m["file"], m["line"])):
            lines.append("| %s | %s:%d | %s | `%s` |" % (mutant["status"].replace("_", " "), mutant["file"], mutant["line"],
                                                        mutant.get("description", ""), mutant.get("source_line", "").replace("|", "\\|")))
    text = "\n".join(lines) + "\n"
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(text)
    if fail and blocking:
        print("::error::%d mutants survived or are on lines no test runs. "
              "Every mutant on a changed line must make a test fail." % len(blocking))
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    lines = commands.add_parser("changed-lines")
    lines.add_argument("--repo", required=True)
    lines.add_argument("--base", required=True)
    lines.add_argument("--out", required=True)
    lines.add_argument("--glob", action="append", default=[])
    checked = commands.add_parser("check")
    checked.add_argument("results")
    checked.add_argument("--fail", action="store_true")
    args = parser.parse_args()
    if args.command == "changed-lines":
        with open(args.out, "w") as f:
            json.dump(changed_lines(args.repo, args.base, args.glob or ["*"]), f)
        return 0
    return check(args.results, args.fail)


if __name__ == "__main__":
    sys.exit(main())
