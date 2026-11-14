#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Which library lines each test ran.

Usage:
  per_test_coverage.py build <coverage dir> <out dir>
      Turns the raw per-test files into <out dir>/<language>.jsonl.
  per_test_coverage.py run-test <binary> [args...]
      A cargo target runner for `cargo nextest run`, so a crate's own tests
      write the same raw files. Set PER_TEST_COVERAGE_DIR, PER_TEST_REPOSITORY
      and PER_TEST_ROOT (the repository's root on this machine).
  per_test_coverage.py lines <jsonl> <test>
      Prints `<file>:<line>` for every line the test ran.
  per_test_coverage.py tests <jsonl> <file>:<line>
      Prints every test that ran the line.

The raw files come from the test server's PerTestCoverage listener, or from
run-test. Either way <coverage dir> holds tests.jsonl (one line per test with
its file number) and <language>/meta.json beside <language>/tests/.

Each line of <language>.jsonl is one test run:
  {"test", "junit_id", "source", "language", "repository", "commit", "status",
   "files": {"<path relative to the library repository>": [<lines hit>]}}
"source" is "test-server" or "local". junit_id is the JUnit unique id, and
empty for local tests.
"""

import concurrent.futures
import glob
import hashlib
import json
import os
import subprocess
import sys
import tempfile

import coverage_report


def lines_hit(lcov):
    """{file: [line, ...]} for every DA line with a count above zero."""
    files, current = {}, None
    for line in lcov.splitlines():
        if line.startswith("SF:"):
            current = files.setdefault(line[3:], set())
        elif line.startswith("DA:") and current is not None:
            number, count = line[3:].split(",")[:2]
            if int(count) > 0:
                current.add(int(number))
    return {path: sorted(hits) for path, hits in sorted(files.items()) if hits}


def llvm_lines(meta, profiles, objects):
    """Lines hit in one test's LLVM profiles."""
    tools = coverage_report.llvm_tools()
    with tempfile.TemporaryDirectory() as scratch:
        profdata = os.path.join(scratch, "test.profdata")
        subprocess.run([os.path.join(tools, "llvm-profdata"), "merge", "-sparse", *profiles, "-o", profdata],
                       check=True, capture_output=True)
        args = [os.path.join(tools, "llvm-cov"), "export", "-format=lcov", "-skip-expansions",
                "-skip-functions",
                # Dependencies and the standard library are not library code, and skipping them halves the time.
                "-ignore-filename-regex=(/\\.cargo/registry/|/rustc/|/\\.rustup/)",
                "-instr-profile=" + profdata, objects[0]]
        for extra in objects[1:]:
            args += ["-object", extra]
        lcov = subprocess.run(args, check=True, capture_output=True, text=True).stdout
    return lines_hit(coverage_report.relative_to_root(lcov, meta))


def jacoco_lines(meta, directory, executions):
    """Lines hit in one test's JaCoCo data."""
    with tempfile.TemporaryDirectory() as scratch:
        xml_path = os.path.join(scratch, "jacoco.xml")
        subprocess.run(["java", "-jar", os.environ["TESTSERVER_JACOCO_CLI"], "report", *executions,
                        "--classfiles", os.path.join(directory, "classes"), "--xml", xml_path],
                       check=True, capture_output=True)
        lcov = coverage_report.jacoco_xml_to_lcov(xml_path, meta["sources"])
    return lines_hit(coverage_report.relative_to_root(lcov, meta))


def build(coverage_dir, out_dir):
    index_path = os.path.join(coverage_dir, "tests.jsonl")
    if not os.path.exists(index_path):
        print("::notice::no per-test coverage in %s" % coverage_dir)
        return
    with open(index_path) as f:
        tests = [json.loads(line) for line in f if line.strip()]
    os.makedirs(out_dir, exist_ok=True)
    for meta_path in sorted(glob.glob(os.path.join(coverage_dir, "*", "meta.json"))):
        directory = os.path.dirname(meta_path)
        with open(meta_path) as f:
            meta = json.load(f)
        if meta["tool"] not in ("llvm", "jacoco"):
            continue
        # A server built without the per-test dump (the Dafny-generated Rust servers) wrote no test files.
        if not glob.glob(os.path.join(directory, "tests", "*")):
            print("::notice::%s gave no per-test coverage" % meta["language"])
            continue

        def convert(test):
            files = {}
            if test["status"] != "skipped":
                if meta["tool"] == "llvm":
                    raw = glob.glob(os.path.join(directory, "tests", test["file"] + ".*.profraw"))
                    objects = [test["object"]] if test.get("object") else meta["objects"]
                    files = llvm_lines(meta, raw, objects) if raw else {}
                else:
                    raw = glob.glob(os.path.join(directory, "tests", test["file"] + ".*.exec"))
                    files = jacoco_lines(meta, directory, raw) if raw else {}
            return {
                "test": test["test"],
                "junit_id": test.get("junit_id", ""),
                "source": test.get("source", "test-server"),
                "language": meta["language"],
                "repository": meta["repository"],
                "commit": meta["commit"],
                "status": test["status"],
                "files": files,
            }

        out_path = os.path.join(out_dir, meta["language"] + ".jsonl")
        with concurrent.futures.ThreadPoolExecutor(os.cpu_count()) as pool, open(out_path, "w") as out:
            for record in pool.map(convert, tests):
                out.write(json.dumps(record) + "\n")
        print("%s: %d tests -> %s" % (meta["language"], len(tests), out_path))


def run_test(command):
    """Runs one nextest test with its own LLVM profile file, then records it."""
    test_name = os.environ.get("NEXTEST_TEST_NAME")
    if not test_name:
        # nextest also runs each binary to list its tests.
        os.execvp(command[0], command)
    directory = os.environ["PER_TEST_COVERAGE_DIR"]
    test = "%s::%s" % (os.environ["NEXTEST_BINARY_ID"], test_name)
    file = hashlib.sha1(test.encode()).hexdigest()[:16]
    tests_dir = os.path.join(directory, "rust", "tests")
    os.makedirs(tests_dir, exist_ok=True)
    meta_path = os.path.join(directory, "rust", "meta.json")
    if not os.path.exists(meta_path):
        meta = {
            "language": "rust",
            "tool": "llvm",
            "repository": os.environ["PER_TEST_REPOSITORY"],
            "commit": subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                                     cwd=os.environ["PER_TEST_ROOT"]).stdout.strip(),
            "root": os.environ["PER_TEST_ROOT"],
            "objects": [],
        }
        # Tests run in parallel, so the first writer wins and the rest see the file.
        temporary = "%s.%d" % (meta_path, os.getpid())
        with open(temporary, "w") as f:
            json.dump(meta, f)
        os.replace(temporary, meta_path)
    env = dict(os.environ, LLVM_PROFILE_FILE=os.path.join(tests_dir, file + ".rust.profraw"))
    status = subprocess.run(command, env=env).returncode
    record = {"test": test, "junit_id": "", "source": "local", "file": file,
              "status": "passed" if status == 0 else "failed", "object": os.path.abspath(command[0])}
    # One short write per line keeps lines from parallel tests whole.
    with open(os.path.join(directory, "tests.jsonl"), "a") as f:
        f.write(json.dumps(record) + "\n")
    sys.exit(status)


def read(jsonl):
    with open(jsonl) as f:
        return [json.loads(line) for line in f if line.strip()]


def main():
    command, args = sys.argv[1], sys.argv[2:]
    if command == "build":
        build(*args)
    elif command == "run-test":
        run_test(args)
    elif command == "lines":
        jsonl, test = args
        for record in read(jsonl):
            if test in (record["test"], record["junit_id"]):
                for path, hits in record["files"].items():
                    for line in hits:
                        print("%s:%d" % (path, line))
    elif command == "tests":
        jsonl, location = args
        path, line = location.rsplit(":", 1)
        for record in read(jsonl):
            if int(line) in record["files"].get(path, []):
                print(record["test"])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
