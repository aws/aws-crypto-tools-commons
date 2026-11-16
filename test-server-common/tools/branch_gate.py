#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fail when a line a pull request changed has a branch no test took.

Usage: branch_gate.py --base <git ref> [--root <dir>] [--exclude <glob>]... <lcov>...

Reads the BRDA branch records of every lcov report and the lines that
`git diff <base>...HEAD` adds or changes. A branch counts as taken when any
report took it, so the reports of the local tests and of the test server
runs add up. Each changed line with an untaken branch is printed as a GitHub
error and the exit code is 1.

SF paths may be absolute or relative to --root (default: the current
directory); --exclude globs match the path relative to --root. A run where
no report has any branch records also fails, because then nothing was checked.
"""

import argparse
import fnmatch
import os
import re
import subprocess
import sys


def read_branches(lcov, root):
    """{(path, line): {branch id: taken}} from lcov text. taken is the
    branch's count, or 0 when the line never ran ("-")."""
    branches = {}
    path = None
    for line in lcov.splitlines():
        if line.startswith("SF:"):
            path = line[3:].strip()
            if os.path.isabs(path):
                path = os.path.relpath(path, root)
        elif line.startswith("BRDA:") and path is not None:
            number, block, branch, taken = line[5:].split(",", 3)
            counts = branches.setdefault((path, int(number)), {})
            counts[(block, branch)] = 0 if taken.strip() == "-" else int(taken)
        elif line.startswith("end_of_record"):
            path = None
    return branches


def merge(reports):
    """One {(path, line): {branch id: taken}} where a branch is taken if any
    report took it."""
    merged = {}
    for report in reports:
        for key, counts in report.items():
            into = merged.setdefault(key, {})
            for branch, taken in counts.items():
                into[branch] = max(into.get(branch, 0), taken)
    return merged


HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_lines(diff):
    """{path: {line numbers}} that a `git diff --unified=0` adds or changes."""
    changed = {}
    path = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            path = target[2:] if target.startswith("b/") else None
        elif path is not None:
            match = HUNK.match(line)
            if match:
                start, count = int(match.group(1)), int(match.group(2) or 1)
                changed.setdefault(path, set()).update(range(start, start + count))
    return changed


def untaken(branches, changed, excludes):
    """[(path, line, untaken, total)] for each changed line with a branch no
    report took, in path and line order."""
    out = []
    for (path, number), counts in sorted(branches.items()):
        if number not in changed.get(path, ()):
            continue
        if any(fnmatch.fnmatch(path, glob) for glob in excludes):
            continue
        missed = sum(1 for taken in counts.values() if taken == 0)
        if missed:
            out.append((path, number, missed, len(counts)))
    return out


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", required=True)
    parser.add_argument("--root", default=".")
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("reports", nargs="+")
    args = parser.parse_args(argv)
    root = os.path.realpath(args.root)

    reports = []
    for report in args.reports:
        with open(report) as f:
            reports.append(read_branches(f.read(), root))
    branches = merge(reports)
    if not branches:
        print("::error::no report has branch records: %s" % " ".join(args.reports))
        return 1

    diff = subprocess.run(["git", "diff", "--unified=0", "--no-color", "--no-renames",
                           args.base + "...HEAD"], cwd=root, check=True,
                          capture_output=True, text=True).stdout
    changed = changed_lines(diff)
    checked = [(path, number) for path, number in branches
               if number in changed.get(path, ())
               and not any(fnmatch.fnmatch(path, glob) for glob in args.exclude)]
    total = sum(len(branches[key]) for key in checked)
    misses = untaken(branches, changed, args.exclude)
    missed = sum(m[2] for m in misses)

    for path, number, count, of in misses:
        print("::error file=%s,line=%d::%d of %d branches on this changed line were never taken"
              % (path, number, count, of))
    print("Changed lines with branches: %d. Branches taken: %d of %d."
          % (len(checked), total - missed, total))
    return 1 if misses else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
