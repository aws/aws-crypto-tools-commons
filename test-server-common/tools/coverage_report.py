#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Turn each Language_Server's raw coverage data into lcov for the dashboard.

Usage: coverage_report.py <coverage dir> <out dir>

The orchestrator writes <coverage dir>/<language>/meta.json for each server it
launched with coverage on (see Coverage.java), and the server writes its raw
data next to it. For each language this writes:

  <out dir>/<language>.lcov  line coverage, paths relative to the library's repository
  <out dir>/<language>.json  {language, repository, commit}

A language whose converter fails or finds no data is reported and skipped;
coverage never fails the test run.
"""

import glob
import json
import os
import subprocess
import sys
import traceback


def run(cmd, **kw):
    print("+ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, **kw)


def llvm_tools():
    libdir = subprocess.run(["rustc", "--print", "target-libdir"], check=True,
                            capture_output=True, text=True).stdout.strip()
    return os.path.join(libdir, "..", "bin")


# Each converter takes (meta, the language's coverage dir) and returns lcov
# text whose SF paths are absolute or relative to the build's working tree.
# relative_to_root() below makes them relative to the library's repository.

def llvm(meta, directory):
    """Rust and anything linking Rust code built with -C instrument-coverage."""
    profiles = glob.glob(os.path.join(directory, "*.profraw"))
    if not profiles:
        return None
    tools = llvm_tools()
    profdata = os.path.join(directory, "merged.profdata")
    run([os.path.join(tools, "llvm-profdata"), "merge", "-sparse", *profiles, "-o", profdata])
    objects = [o for o in meta["objects"] if os.path.exists(o)]
    if not objects:
        raise RuntimeError("none of the instrumented objects exist: %s" % meta["objects"])
    args = [os.path.join(tools, "llvm-cov"), "export", "-format=lcov", "-instr-profile=" + profdata, objects[0]]
    for extra in objects[1:]:
        args += ["-object", extra]
    return run(args, capture_output=True, text=True).stdout


CONVERTERS = {
    "llvm": llvm,
}


def relative_to_root(lcov, meta):
    """Keep only files inside the library's repository, with repo-relative paths.

    A binary built on another runner names its sources under that runner's
    workspace, so a path also matches on the repository root relative to this
    workspace.
    """
    root = os.path.realpath(meta["root"])
    markers = [root + "/"]
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace and root.startswith(os.path.realpath(workspace) + "/"):
        markers.append("/" + os.path.relpath(root, os.path.realpath(workspace)) + "/")
    out, keep = [], False
    for line in lcov.splitlines(keepends=True):
        if line.startswith("SF:"):
            path = line[3:].strip()
            if not os.path.isabs(path):
                path = os.path.normpath(os.path.join(meta.get("library", root), path))
            keep = False
            if path.startswith(markers[0]):
                line, keep = "SF:" + path[len(markers[0]):] + "\n", True
            elif len(markers) > 1 and markers[1] in path:
                line, keep = "SF:" + path.split(markers[1], 1)[1] + "\n", True
        if keep:
            out.append(line)
            if line.startswith("end_of_record"):
                keep = False
    return "".join(out)


def main():
    coverage_dir, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    for meta_path in sorted(glob.glob(os.path.join(coverage_dir, "*", "meta.json"))):
        directory = os.path.dirname(meta_path)
        meta = json.load(open(meta_path))
        language = meta["language"]
        try:
            convert = CONVERTERS.get(meta["tool"])
            if convert is None:
                raise RuntimeError("no converter for tool '%s'" % meta["tool"])
            lcov = convert(meta, directory)
            if not lcov:
                print("::notice::%s wrote no coverage data" % language)
                continue
            lcov = relative_to_root(lcov, meta)
            files = lcov.count("\nSF:") + lcov.startswith("SF:")
            if not files:
                print("::warning::%s coverage named no files in %s" % (language, meta["root"]))
                continue
            with open(os.path.join(out_dir, language + ".lcov"), "w") as f:
                f.write(lcov)
            with open(os.path.join(out_dir, language + ".json"), "w") as f:
                json.dump({k: meta[k] for k in ("language", "repository", "commit")}, f)
            print("%s: %d files from %s@%s" % (language, files, meta["repository"], meta["commit"]))
        except Exception:
            print("::warning::%s coverage report failed" % language)
            traceback.print_exc()


if __name__ == "__main__":
    main()
