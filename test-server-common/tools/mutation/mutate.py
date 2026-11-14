#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Mutation testing of a Rust library against the test server Tests and the crate's own tests.

Usage:
  mutate.py --repo <rust repo> --crates mpl[,esdk] --server <dir>:<binary>
            --tests-jvm <tests-jvm.json> --per-test <jsonl>[,<jsonl>...]
            --work <dir> --out <results.json>
            [--changed-since <git ref>] [--servers N] [--cache <file>]
            [--sample N] [--no-select] [--no-stop] [--relaunch] [--new-jvm]

A mutant is a small change to the library, such as `<` turned into `<=`.
A test kills a mutant when it fails with the mutant on. A mutant that no test
kills shows a change the tests do not notice.

How this stays fast on one machine:
  - Every mutant is built into one throwaway copy of the library, each behind
    `test_server_control::mutant::is_on(<id>)` (rust-schemata/). One build, not one per mutant.
  - The mutated server starts once and switches mutants on `POST /control/mutant`.
  - Each mutant runs only the tests that ran its line on the unmutated library
    (the per-test coverage files). A mutant on a line no test runs costs nothing.
  - It stops at the first test that kills, and tries the test that killed the
    mutant last time first, then the tests that ran the fewest lines.
  - A cache keyed by the mutant, the library source and the test source skips
    mutants whose answer cannot have changed.
  - --changed-since keeps only mutants on lines changed since a git ref.
  - --servers N runs N mutated servers, each with its own Tests JVM.
The --no-select, --no-stop, --relaunch and --new-jvm flags turn single steps off,
to measure what each one saves.
"""

import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
import random
import re
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMATA_DIR = os.path.join(HERE, "rust-schemata")
CONTROL_CRATE = "test-server-control"
LOCAL_TIMEOUT_SECONDS = 60
SERVER_TIMEOUT_SECONDS = 60


def log(message):
    print("[mutate] " + message, flush=True)


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


class Clock:
    """Wall time per phase, for the speed report."""

    def __init__(self):
        self.phases = collections.OrderedDict()

    def phase(self, name):
        clock = self

        class Timer:
            def __enter__(self):
                self.start = time.monotonic()

            def __exit__(self, *_):
                clock.phases[name] = clock.phases.get(name, 0) + time.monotonic() - self.start

        return Timer()


# ---------------------------------------------------------------- the mutated copy

def tracked_sources(repo, crate):
    listed = run(["git", "-C", repo, "ls-files", crate + "/src"], capture_output=True, text=True).stdout.split()
    return sorted(path for path in listed if path.endswith(".rs"))


def schemata_tool():
    target = os.environ.get("MUTATION_SCHEMATA_TARGET", os.path.join(SCHEMATA_DIR, "target"))
    run(["cargo", "build", "--quiet", "--release", "--manifest-path", os.path.join(SCHEMATA_DIR, "Cargo.toml"),
         "--target-dir", target])
    return os.path.join(target, "release", "rust-mutant-schemata")


def copy_repo(repo, copy):
    os.makedirs(copy, exist_ok=True)
    run(["rsync", "-a", "--delete", "--exclude", "target", "--exclude", ".git", "--exclude", "*.profraw",
         os.path.realpath(repo) + "/", copy + "/"])


def write_mutants(tool, repo, copy, crates, skip, lines_file, out):
    """Rewrites the copy's crate sources with every mutant; returns the mutant list."""
    for crate in crates:
        for path in tracked_sources(repo, crate):
            with open(os.path.join(repo, path), "rb") as original, open(os.path.join(copy, path), "wb") as target:
                target.write(original.read())
    files = [path for crate in crates for path in tracked_sources(repo, crate)]
    cmd = [tool, "--root", copy, "--out", out, "--skip", ",".join(map(str, sorted(skip)))]
    if lines_file:
        cmd += ["--lines", lines_file]
    run(cmd + files)
    with open(out) as f:
        return json.load(f)


def add_control_dependency(copy, crates):
    for crate in crates:
        path = os.path.join(copy, crate, "Cargo.toml")
        with open(path) as f:
            text = f.read()
        if CONTROL_CRATE in text:
            continue
        line = '%s = { path = "%s" }\n' % (CONTROL_CRATE, os.path.relpath(os.path.join(copy, CONTROL_CRATE), os.path.join(copy, crate)))
        text = text.replace("\n[dependencies]\n", "\n[dependencies]\n" + line, 1)
        with open(path, "w") as f:
            f.write(text)


def build_env(target_dir):
    # --cap-lints: the mutants trip lints (unreachable code, unused values) that would fail a -D warnings build.
    return dict(os.environ, CARGO_TARGET_DIR=target_dir, RUSTFLAGS="--cfg testserver_mutants --cap-lints=allow")


REWRITTEN = {}


def mutant_at(copy, path, line):
    """The id of the mutant whose switch is closest above `line` in a rewritten file."""
    if path not in REWRITTEN:
        with open(os.path.join(copy, path)) as f:
            REWRITTEN[path] = f.read().splitlines()
    lines = REWRITTEN[path]
    for number in range(min(line, len(lines)), 0, -1):
        found = re.findall(r"mutant::is_on\((\d+)u32\)", lines[number - 1])
        if found:
            return int(found[-1])
    return None


def unviable_mutants(copy, crates, server_dir, target_dir):
    """Ids of mutants that do not compile, from one `cargo check` per crate and the server."""
    found, other = set(), []
    for directory in [os.path.join(copy, crate) for crate in crates] + [os.path.join(copy, server_dir)]:
        result = subprocess.run(["cargo", "check", "--tests", "--message-format=json"], cwd=directory,
                                env=build_env(target_dir), capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if not line.startswith("{"):
                continue
            message = json.loads(line)
            if message.get("reason") != "compiler-message" or message["message"]["level"] != "error":
                continue
            spans = [span for span in message["message"]["spans"] if span["is_primary"]] or message["message"]["spans"]
            ids = set()
            for span in spans:
                path = os.path.relpath(os.path.normpath(os.path.join(directory, span["file_name"])), copy)
                mutant = mutant_at(copy, path, span["line_start"])
                if mutant is not None:
                    ids.add(mutant)
            if ids:
                found |= ids
            elif message["message"]["spans"]:
                other.append(message["message"]["rendered"])
        if result.returncode != 0 and not found and other:
            raise RuntimeError("the mutated copy fails to build for a reason no mutant explains:\n" + "\n".join(other[:5]))
    return found


def prepare(args, clock, tool, lines_file, skip):
    """Writes and builds the mutated copy, leaving out the `skip` ids.

    Returns (ids that do not compile, local test binaries).
    """
    copy = os.path.join(args.work, "copy")
    target_dir = os.path.join(args.work, "target")
    server_dir, _ = args.server.split(":")
    unviable = set()
    while True:
        with clock.phase("write mutants"):
            write_mutants(tool, args.repo, copy, args.crates, skip | unviable, lines_file,
                          os.path.join(args.work, "mutants-built.json"))
            REWRITTEN.clear()
        with clock.phase("find mutants that do not compile"):
            bad = unviable_mutants(copy, args.crates, server_dir, target_dir) - unviable
        log("%d do not compile" % len(bad))
        if not bad:
            break
        unviable |= bad
    with clock.phase("build"):
        run(["cargo", "build", "--release", "--quiet"], cwd=os.path.join(copy, server_dir), env=build_env(target_dir))
        binaries = {}
        for crate in args.crates:
            # --release shares the dependencies the server build just compiled.
            result = run(["cargo", "test", "--release", "--no-run", "--message-format=json"], cwd=os.path.join(copy, crate),
                         env=build_env(target_dir), capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if not line.startswith("{"):
                    continue
                message = json.loads(line)
                if message.get("reason") != "compiler-artifact" or not message.get("executable") or not message["profile"]["test"]:
                    continue
                package = re.sub(r".*[/#]([^@#/]+)@.*", r"\1", message["package_id"])
                target = message["target"]
                binary_id = package if "lib" in target["kind"] else "%s::%s" % (package, target["name"])
                binaries[binary_id] = (message["executable"], os.path.join(copy, crate))
    return unviable, binaries


# ---------------------------------------------------------------- which tests to run

def load_coverage(paths):
    """{(file, line): [test record, ...]} from per-test coverage files of the unmutated library."""
    by_line = collections.defaultdict(list)
    for path in paths:
        with open(path) as f:
            for text in f:
                record = json.loads(text)
                if record["status"] != "passed":
                    continue
                record["size"] = sum(len(lines) for lines in record["files"].values())
                for file, lines in record["files"].items():
                    for line in lines:
                        by_line[(file, line)].append(record)
    return by_line


def changed_lines(repo, base):
    """{file: [line, ...]} for lines added or changed since this branch left `base`."""
    fork = run(["git", "-C", repo, "merge-base", base, "HEAD"], capture_output=True, text=True).stdout.strip()
    diff = run(["git", "-C", repo, "diff", "-U0", fork, "--", "*.rs"], capture_output=True, text=True).stdout
    lines, file = collections.defaultdict(list), None
    for text in diff.splitlines():
        if text.startswith("+++ "):
            file = text[6:] if text.startswith("+++ b/") else None
        elif text.startswith("@@") and file:
            start, _, count = re.match(r"@@ -\S+ \+(\d+)(,(\d+))? @@", text).groups()
            for line in range(int(start), int(start) + (int(count) if count is not None else 1)):
                lines[file].append(line)
    return dict(lines)


def plan_tests(mutant, by_line, all_tests, args, killer):
    """The tests to try on a mutant, cheapest likely killer first. Local tests start in ~1 ms, so they go first."""
    if args.no_select:
        tests = list(all_tests)
    else:
        tests = list({record["test"]: record for record in by_line.get((mutant["file"], mutant["line"]), [])}.values())
    tests.sort(key=lambda record: (killer not in (record["test"], record["junit_id"]), record["source"] != "local", record["size"], record["test"]))
    return tests


# ---------------------------------------------------------------- running

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, binary, cwd):
        self.binary, self.cwd, self.process, self.port = binary, cwd, None, None

    def start(self):
        self.port = free_port()
        self.process = subprocess.Popen([self.binary, str(self.port)], cwd=self.cwd,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.02)
        raise RuntimeError("the mutated server did not start on port %d" % self.port)

    def stop(self):
        if self.process:
            self.process.kill()
            self.process.wait()
            self.process = None

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.port


def run_local(mutant_id, record, binaries):
    # The test name is "<binary id>::<test path>", and a binary id can hold one `::` itself.
    parts = record["test"].split("::")
    for split in range(len(parts) - 1, 0, -1):
        binary_id, name = "::".join(parts[:split]), "::".join(parts[split:])
        if binary_id in binaries:
            break
    else:
        raise RuntimeError("no test binary for " + record["test"])
    executable, cwd = binaries[binary_id]
    env = dict(os.environ, TESTSERVER_MUTANT=str(mutant_id))
    try:
        result = subprocess.run([executable, "--exact", name, "--test-threads", "1", "-q"], cwd=cwd, env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=LOCAL_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return "timed_out"
    return "passed" if result.returncode == 0 else "killed"


def run_local_tests(mutant, tests, binaries, stop_early):
    started, run_count = time.monotonic(), 0
    outcome = {"status": "survived"}
    for record in tests:
        if record["source"] != "local":
            continue
        run_count += 1
        status = run_local(mutant["id"], record, binaries)
        if status != "passed":
            outcome = {"status": status, "killed_by": record["test"]}
            if stop_early:
                break
    outcome.update(tests_run=run_count, seconds=time.monotonic() - started)
    return outcome


def run_server_tests(args, jobs, binary, server_cwd, tests_jvm, results_path, clock):
    """Runs [(mutant id, [junit ids])] through MutantRunner on args.servers mutated servers."""
    if not jobs:
        return {}
    shards = [jobs[i::args.servers] for i in range(args.servers)]

    def run_shard(index, shard):
        out = "%s.%d" % (results_path, index)
        open(out, "w").close()
        remaining, results = list(shard), {}
        one_at_a_time = args.relaunch or args.new_jvm
        server = Server(binary, server_cwd)
        server.start()
        while remaining:
            batch = remaining[:1] if one_at_a_time else remaining
            plan = {
                "servers": [server.url],
                "system_properties": system_properties(tests_jvm, server.url),
                "timeout_seconds": SERVER_TIMEOUT_SECONDS,
                "stop_at_first_kill": not args.no_stop,
                "mutants": [{"id": mutant_id, "tests": tests} for mutant_id, tests in batch],
            }
            plan_path = "%s.plan.%d.json" % (results_path, index)
            with open(plan_path, "w") as f:
                json.dump(plan, f)
            exit_code = subprocess.run(["java", "-cp", tests_jvm["class_path"],
                                        "aws.cryptography.testserver.tests.MutantRunner", plan_path, out]).returncode
            before = len(results)
            with open(out) as f:
                for text in f:
                    record = json.loads(text)
                    results[record["id"]] = record
            if len(results) == before:
                raise RuntimeError("MutantRunner exited %d without a result; see its output" % exit_code)
            remaining = [job for job in remaining if job[0] not in results]
            # A timed-out mutant may have left the server looping, so it gets a fresh one.
            if args.relaunch or exit_code == 3:
                server.stop()
                if remaining:
                    server.start()
        server.stop()
        return results

    merged = {}
    with concurrent.futures.ThreadPoolExecutor(args.servers) as pool:
        for shard_results in pool.map(lambda pair: run_shard(*pair), enumerate(shards)):
            merged.update(shard_results)
    return merged


def system_properties(tests_jvm, url):
    """The Tests JVM's testserver.* properties, with the rust target pointed at the mutated server."""
    properties = dict(tests_jvm["system_properties"])
    properties.pop("testserver.featureGateLog", None)
    targets = []
    for entry in properties["testserver.targets"].split(","):
        key, _, _ = entry.partition("=")
        if key.split(":")[0] == "rust":
            targets.append(key + "=" + url)
    properties["testserver.targets"] = ",".join(targets)
    properties.pop("testserver.focus", None)
    return properties


# ---------------------------------------------------------------- cache

def tree_hash(repo, paths):
    """A hash of the tracked files under `paths`, including uncommitted changes."""
    files = run(["git", "-C", repo, "ls-files", "--", *paths], capture_output=True, text=True).stdout.split()
    digest = hashlib.sha256()
    for path in sorted(files):
        full = os.path.join(repo, path)
        if os.path.isfile(full):
            digest.update(path.encode() + b"\0")
            with open(full, "rb") as f:
                digest.update(hashlib.sha256(f.read()).digest())
    return digest.hexdigest()


def mutant_key(mutant, code_hash):
    described = "%s:%d:%d:%s:%s" % (mutant["file"], mutant["line"], mutant["column"], mutant["kind"], mutant["description"])
    return hashlib.sha256((described + "\0" + code_hash).encode()).hexdigest()


# ---------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--repository", default="aws/aws-crypto-tools-rust", help="owner/name, for links to the code")
    parser.add_argument("--crates", required=True, type=lambda s: s.split(","))
    parser.add_argument("--server", required=True, help="<server dir>:<binary name>, relative to --repo")
    parser.add_argument("--tests-jvm", required=True)
    parser.add_argument("--tests-source", default=[], type=lambda s: s.split(","),
                        help="test directories whose change invalidates the cache")
    parser.add_argument("--per-test", required=True, type=lambda s: s.split(","))
    parser.add_argument("--work", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--changed-since")
    parser.add_argument("--servers", type=int, default=1)
    parser.add_argument("--jobs", type=int, default=os.cpu_count(), help="mutants whose local tests run at once")
    parser.add_argument("--cache")
    parser.add_argument("--sample", type=int, help="run only this many mutants, chosen at random with a fixed seed")
    parser.add_argument("--no-select", action="store_true", help="run every test on every mutant")
    parser.add_argument("--no-stop", action="store_true", help="keep running tests after one kills")
    parser.add_argument("--relaunch", action="store_true", help="start a new server and JVM for every mutant")
    parser.add_argument("--new-jvm", action="store_true", help="start a new Tests JVM for every mutant")
    args = parser.parse_args()
    args.work = os.path.abspath(args.work)
    os.makedirs(args.work, exist_ok=True)

    clock = Clock()
    total_start = time.monotonic()
    with clock.phase("build the schemata tool"):
        tool = schemata_tool()
    lines_file = None
    if args.changed_since:
        lines_file = os.path.join(args.work, "changed-lines.json")
        with open(lines_file, "w") as f:
            json.dump(changed_lines(args.repo, args.changed_since), f)
    with clock.phase("copy"):
        copy_repo(args.repo, os.path.join(args.work, "copy"))
        add_control_dependency(os.path.join(args.work, "copy"), args.crates)
    with clock.phase("write mutants"):
        written = write_mutants(tool, args.repo, os.path.join(args.work, "copy"), args.crates, set(), lines_file,
                                os.path.join(args.work, "mutants.json"))
    mutants, skipped_by_rule = written["mutants"], written["skipped"]

    code_hash = hashlib.sha256((tree_hash(args.repo, args.crates + [CONTROL_CRATE, args.server.split(":")[0]])
                                + "".join(tree_hash(directory, ["."]) for directory in args.tests_source)).encode()).hexdigest()
    # cache: results by mutant and exact code. killers: the test that last killed a mutant
    # at the same spot, kept across code changes to pick which test to try first.
    stored = {"results": {}, "killers": {}}
    if args.cache and os.path.exists(args.cache):
        with open(args.cache) as f:
            stored = json.load(f)
    cache, killers = stored["results"], stored["killers"]
    keys = {mutant["id"]: mutant_key(mutant, code_hash) for mutant in mutants}
    spots = {mutant["id"]: mutant_key(mutant, "") for mutant in mutants}
    chosen = mutants
    if args.sample and args.sample < len(mutants):
        chosen = sorted(random.Random(0).sample(mutants, args.sample), key=lambda mutant: mutant["id"])
    results = {}
    for mutant in chosen:
        previous = cache.get(keys[mutant["id"]])
        if previous and previous.get("code") == code_hash:
            results[mutant["id"]] = dict(previous["result"], cached=True)

    # Cached and unsampled mutants stay out of the build, so it compiles only what runs.
    chosen_ids = {mutant["id"] for mutant in chosen}
    skip = {mutant["id"] for mutant in mutants if mutant["id"] not in chosen_ids or mutant["id"] in results}
    unviable, binaries = set(), {}
    if len(skip) < len(mutants):
        unviable, binaries = prepare(args, clock, tool, lines_file, skip)
    for mutant_id in unviable:
        results[mutant_id] = {"status": "unviable", "tests_run": 0, "seconds": 0}
        cache[keys[mutant_id]] = {"code": code_hash, "result": results[mutant_id]}

    with open(args.tests_jvm) as f:
        tests_jvm = json.load(f)
    by_line = load_coverage(args.per_test)
    all_tests = list({record["test"]: record for records in by_line.values() for record in records}.values())

    to_run = []
    for mutant in chosen:
        if mutant["id"] in results:
            continue
        tests = plan_tests(mutant, by_line, all_tests, args, killers.get(spots[mutant["id"]]))
        if not tests:
            results[mutant["id"]] = {"status": "not_covered", "tests_run": 0, "seconds": 0}
            cache[keys[mutant["id"]]] = {"code": code_hash, "result": results[mutant["id"]]}
        else:
            to_run.append((mutant, tests, keys[mutant["id"]]))
    log("%d mutants: %d cached, %d do not compile, %d not covered, %d to run" % (
        len(chosen), sum(1 for r in results.values() if r.get("cached")), len(unviable),
        sum(1 for r in results.values() if r["status"] == "not_covered" and not r.get("cached")), len(to_run)))

    stop_early = not args.no_stop
    with clock.phase("run local tests"):
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            local = dict(zip([mutant["id"] for mutant, _, _ in to_run],
                             pool.map(lambda job: run_local_tests(job[0], job[1], binaries, stop_early), to_run)))

    server_dir, server_binary = args.server.split(":")
    jobs = []
    for mutant, tests, _ in to_run:
        if stop_early and local[mutant["id"]]["status"] != "survived":
            continue
        server_tests = [record["junit_id"] for record in tests if record["source"] == "test-server"]
        if server_tests:
            jobs.append((mutant["id"], server_tests))
    with clock.phase("run test server tests"):
        server = run_server_tests(args, jobs, os.path.join(args.work, "target", "release", server_binary),
                                  os.path.join(args.work, "copy", server_dir), tests_jvm,
                                  os.path.join(args.work, "server-results.jsonl"), clock)

    for mutant, tests, key in to_run:
        outcome = dict(local[mutant["id"]])
        remote = server.get(mutant["id"])
        if remote:
            outcome["tests_run"] += remote["tests_run"]
            outcome["seconds"] += remote["seconds"]
            if outcome["status"] == "survived":
                outcome["status"] = remote["status"]
                if "killed_by" in remote:
                    outcome["killed_by"] = remote["killed_by"]
        results[mutant["id"]] = outcome
        cache[key] = {"code": code_hash, "result": {k: v for k, v in outcome.items() if k != "cached"}}
        if "killed_by" in outcome:
            killers[spots[mutant["id"]]] = outcome["killed_by"]

    if args.cache:
        with open(args.cache, "w") as f:
            json.dump(stored, f)

    for mutant in mutants:
        if mutant["id"] in results:
            mutant.update(results[mutant["id"]])
        else:
            mutant["status"] = "not_sampled"
        with open(os.path.join(args.repo, mutant["file"])) as f:
            source = f.read().splitlines()
        mutant["source_line"] = source[mutant["line"] - 1].strip() if mutant["line"] <= len(source) else ""

    counted = [mutant for mutant in mutants if mutant["status"] not in ("not_sampled",)]
    summary = {
        "repository": args.repository,
        "commit": run(["git", "-C", args.repo, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
        "crates": args.crates,
        "mutants": len(mutants),
        "statuses": dict(collections.Counter(mutant["status"] for mutant in counted)),
        "ran": len(to_run),
        "cached": sum(1 for r in results.values() if r.get("cached")),
        "skipped_by_rule": skipped_by_rule,
        "seconds": time.monotonic() - total_start,
        "phases": clock.phases,
        "servers": args.servers,
        "jobs": args.jobs,
        "flags": {k: getattr(args, k) for k in ("no_select", "no_stop", "relaunch", "new_jvm", "sample", "changed_since")},
        "tests_run": sum(r.get("tests_run", 0) for r in results.values()),
    }
    with open(args.out, "w") as f:
        json.dump({"summary": summary, "mutants": mutants}, f, indent=1)
    log(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
