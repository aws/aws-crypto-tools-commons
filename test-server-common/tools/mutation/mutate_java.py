#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Mutation testing of a Java library against the test server Tests and its own tests.

Usage:
  mutate_java.py --repo <library repo> --repository <owner/name> --library esdk
                 --coverage-dir <raw per-test coverage dir> --per-test <java.jsonl>
                 --tools <jvm-mutants dir> --work <dir> --out <results.json>
                 [--pit-xml <mutations.xml>] [--changed-since <git ref>] [--fail-on-survivors]

A mutant is a small change to the library, such as `<` turned into `<=`.
A test kills a mutant when it fails with the mutant on.

How it works:
  - The per-test coverage pass has already run the Tests against the unmutated
    server, so <coverage dir>/java/meta.json says how the server was started and
    <per-test> says which library lines each Test ran.
  - This starts that server again with the MutantSwitch agent (jvm-mutants/),
    then ListMutants writes PIT's mutants of the classes the server loaded.
  - --pit-xml is a pitest-maven mutations.xml from the library's own tests.
    A mutant PIT killed counts as killed. Only the rest run the Tests.
  - Each mutant runs only the Tests that ran its line, through MutantRunner,
    which switches the mutant on with `POST /control/mutant` to the agent.
  - --changed-since keeps only mutants on lines changed since a git ref.

--fail-on-survivors exits 1 when a mutant survives. With --pit-xml it also
exits 1 when a mutant sits on a line no test runs. Without it, such a mutant is
reported as not_covered only, because the library's own tests may kill it.
results.py describes results.json.
"""

import argparse
import collections
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ElementTree

import results as results_file

SERVER_TIMEOUT_SECONDS = 60
START_TIMEOUT_SECONDS = 600
TIMED_OUT_EXIT = 3


def log(message):
    print("[mutate_java] " + message, flush=True)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def listening(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        return True
    except OSError:
        return False


class Server:
    """The library's test server, started the way the per-test pass started it, plus the MutantSwitch agent."""

    def __init__(self, launch, agent, dir, log_path):
        self.launch, self.agent, self.dir, self.log_path = launch, agent, dir, log_path
        self.process = None

    def start(self):
        self.port, self.control_port = free_port(), free_port()
        os.makedirs(self.dir, exist_ok=True)
        init = os.path.join(self.dir, "mutants.init.gradle")
        argument = "-javaagent:%s=port=%d,dir=%s" % (self.agent, self.control_port, self.dir)
        with open(init, "w") as f:
            f.write("allprojects {\n    tasks.withType(JavaExec).configureEach {\n        jvmArgs %s\n    }\n}\n"
                    % json.dumps(argument))
        command = [part for part in self.launch["command"] if not part.startswith("--args=")]
        command += ["--args=%d" % self.port, "-I", init]
        env = dict(os.environ)
        if self.launch.get("java_home"):
            env["JAVA_HOME"] = self.launch["java_home"]
        with open(self.log_path, "a") as out:
            self.process = subprocess.Popen(command, cwd=self.launch["directory"], env=env, stdout=out,
                                            stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + START_TIMEOUT_SECONDS
        while not (listening(self.port) and listening(self.control_port)):
            if self.process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("the server did not start; see " + self.log_path)
            time.sleep(0.5)

    def stop(self):
        if self.process:
            # Gradle runs the server in a child JVM, so the whole group goes.
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait()
            self.process = None

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.port

    @property
    def control_url(self):
        return "http://127.0.0.1:%d" % self.control_port


def switch(server, mutant_id):
    """Turns a mutant on; returns None, or the agent's reason when the JVM refuses the mutant."""
    request = urllib.request.Request(server.control_url + "/control/mutant", data=str(mutant_id).encode(), method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30):
            return None
    except urllib.error.HTTPError as error:
        return error.read().decode() or str(error)


def list_mutants(args, server, lines):
    """Runs ListMutants on the classes the server loaded; returns the mutant list."""
    out = server.dir
    command = ["java", "-cp", "%s:%s" % (args.jar, args.tools_classpath),
               "aws.cryptography.testserver.mutation.ListMutants", os.path.join(out, "classpath.txt"),
               args.repo, ":".join(os.path.join(args.repo, root) for root in args.sources), out]
    if lines is not None:
        lines_path = os.path.join(args.work, "changed-lines.tsv")
        with open(lines_path, "w") as f:
            for file, numbers in lines.items():
                for number in numbers:
                    f.write("%s\t%d\n" % (file, number))
        command.append(lines_path)
    subprocess.run(command, check=True)
    mutants = []
    with open(os.path.join(out, "mutants.tsv")) as f:
        for text in f:
            fields = text.rstrip("\n").split("\t")
            mutant_id, file, line, mutator, method, descriptor, indexes, class_name, description = fields
            mutants.append({"id": int(mutant_id), "file": file, "line": int(line), "kind": mutator.rsplit(".", 1)[-1],
                            "description": description, "function": method,
                            "pit_key": (class_name, method, descriptor, mutator, indexes)})
    return mutants


def pit_results(path):
    """{pit key: (status, killing test)} from a pitest-maven mutations.xml."""
    found = {}
    for mutation in ElementTree.parse(path).getroot().iter("mutation"):
        key = (mutation.findtext("mutatedClass"), mutation.findtext("mutatedMethod"),
               mutation.findtext("methodDescription"), mutation.findtext("mutator"),
               ",".join(index.text for index in mutation.find("indexes").iter("index")))
        found[key] = (mutation.get("status"), (mutation.findtext("killingTest") or "").split("|")[0])
    return found


def load_coverage(path):
    """{(file, line): [passing test-server test records]}."""
    by_line = collections.defaultdict(list)
    with open(path) as f:
        for text in f:
            record = json.loads(text)
            if record["status"] != "passed" or record.get("source", "test-server") != "test-server":
                continue
            record["size"] = sum(len(lines) for lines in record["files"].values())
            for file, lines in record["files"].items():
                for line in lines:
                    by_line[(file, line)].append(record)
    return by_line


def system_properties(tests_jvm, url):
    """The Tests JVM's testserver.* properties, with only the java target, pointed at the mutated server."""
    properties = dict(tests_jvm["system_properties"])
    properties.pop("testserver.featureGateLog", None)
    properties.pop("testserver.focus", None)
    targets = []
    for entry in properties["testserver.targets"].split(","):
        key, _, _ = entry.partition("=")
        if key.split(":")[0] == "java":
            targets.append(key + "=" + url)
    properties["testserver.targets"] = ",".join(targets)
    return properties


def run_tests(server, jobs, tests_jvm, work):
    """Runs [(mutant id, [junit ids])] through MutantRunner; returns {id: result}."""
    results, remaining = {}, list(jobs)
    out = os.path.join(work, "server-results.jsonl")
    open(out, "w").close()
    while remaining:
        plan = {"servers": [server.control_url], "system_properties": system_properties(tests_jvm, server.url),
                "timeout_seconds": SERVER_TIMEOUT_SECONDS, "stop_at_first_kill": True,
                "mutants": [{"id": mutant_id, "tests": tests} for mutant_id, tests in remaining]}
        plan_path = os.path.join(work, "plan.json")
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
        # A timed-out mutant may have left the server looping, so the rest get a fresh one.
        if exit_code == TIMED_OUT_EXIT and remaining:
            server.stop()
            server.start()
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--repository", required=True, help="owner/name, for links to the code")
    parser.add_argument("--library", required=True, help="esdk, mpl, dbesdk or prim")
    parser.add_argument("--sources", default=["src/main/java"], type=lambda s: s.split(","),
                        help="the library's source roots, relative to --repo")
    parser.add_argument("--coverage-dir", required=True, help="the per-test pass's TESTSERVER_COVERAGE_DIR")
    parser.add_argument("--per-test", required=True, help="java.jsonl from per_test_coverage.py build")
    parser.add_argument("--tools", required=True, help="the built jvm-mutants directory")
    parser.add_argument("--work", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--pit-xml")
    parser.add_argument("--changed-since")
    parser.add_argument("--fail-on-survivors", action="store_true")
    args = parser.parse_args()
    args.work = os.path.abspath(args.work)
    args.repo = os.path.abspath(args.repo)
    os.makedirs(args.work, exist_ok=True)
    args.jar = os.path.join(args.tools, "target", "jvm-mutants-1.0.0.jar")
    with open(os.path.join(args.tools, "target", "classpath.txt")) as f:
        args.tools_classpath = f.read().strip()

    started, phases = time.monotonic(), {}
    with open(os.path.join(args.coverage_dir, "java", "meta.json")) as f:
        launch = json.load(f)["launch"]
    with open(os.path.join(args.coverage_dir, "tests-jvm.json")) as f:
        tests_jvm = json.load(f)
    lines = None
    if args.changed_since:
        lines = results_file.changed_lines(args.repo, args.changed_since, ["*.java"])

    server = Server(launch, args.jar, os.path.join(args.work, "server"), os.path.join(args.work, "server.log"))
    phase = time.monotonic()
    server.start()
    phases["start the server"] = time.monotonic() - phase
    try:
        phase = time.monotonic()
        mutants = list_mutants(args, server, lines)
        phases["list mutants"] = time.monotonic() - phase
        local = pit_results(args.pit_xml) if args.pit_xml else {}
        by_line = load_coverage(args.per_test)

        phase = time.monotonic()
        jobs = []
        for mutant in mutants:
            status, killer = local.get(mutant["pit_key"], (None, ""))
            if status in ("KILLED", "TIMED_OUT", "MEMORY_ERROR"):
                mutant.update(status="killed" if status == "KILLED" else "timed_out", killed_by=killer, tests_run=1)
                continue
            # A mutant the JVM will not load (it changes the class shape) cannot run.
            reason = switch(server, mutant["id"])
            if reason:
                mutant.update(status="unviable", reason=reason, tests_run=0)
                continue
            tests = sorted({record["junit_id"]: record for record in by_line.get((mutant["file"], mutant["line"]), [])}.values(),
                           key=lambda record: (record["size"], record["test"]))
            if tests:
                jobs.append((mutant["id"], [record["junit_id"] for record in tests]))
            else:
                mutant.update(status="survived" if status == "SURVIVED" else "not_covered", tests_run=0)
        switch(server, 0)
        phases["check mutants"] = time.monotonic() - phase
        log("%d mutants: %d killed by the library's tests, %d to run against the server"
            % (len(mutants), sum(1 for m in mutants if m.get("status") in ("killed", "timed_out")), len(jobs)))

        phase = time.monotonic()
        remote = run_tests(server, jobs, tests_jvm, args.work)
        phases["run test server tests"] = time.monotonic() - phase
    finally:
        server.stop()

    for mutant in mutants:
        if mutant["id"] in remote:
            result = remote[mutant["id"]]
            mutant.update(status=result["status"], tests_run=result["tests_run"], seconds=result["seconds"])
            if "killed_by" in result:
                mutant["killed_by"] = result["killed_by"]
        mutant.pop("pit_key")
        with open(os.path.join(args.repo, mutant["file"])) as f:
            source = f.read().splitlines()
        mutant["source_line"] = source[mutant["line"] - 1].strip() if mutant["line"] <= len(source) else ""

    commit = subprocess.run(["git", "-C", args.repo, "rev-parse", "HEAD"], check=True, capture_output=True,
                            text=True).stdout.strip()
    summary = {
        "repository": args.repository, "commit": commit, "language": "java", "library": args.library,
        "tool": "mutate_java.py", "scope": "changed" if args.changed_since else "full",
        "mutants": len(mutants), "statuses": results_file.counts(mutants),
        "local_results": bool(args.pit_xml), "seconds": time.monotonic() - started, "phases": phases,
        "tests_run": sum(mutant.get("tests_run", 0) for mutant in mutants),
    }
    with open(args.out, "w") as f:
        json.dump({"summary": summary, "mutants": mutants}, f, indent=1)
    log(json.dumps(summary, indent=1))
    if args.pit_xml:
        return results_file.check(args.out, args.fail_on_survivors)
    # Without the library's own results, a line no Test runs may still be one its own tests kill.
    results_file.check(args.out, False)
    survivors = [mutant for mutant in mutants if mutant["status"] == "survived"]
    if args.fail_on_survivors and survivors:
        print("::error::%d mutants survived every test server Test that runs their line." % len(survivors))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
