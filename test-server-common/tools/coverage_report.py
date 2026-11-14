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
import shutil
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
    # Per-test files under tests/ hold the counts the server zeroed after each test.
    profiles = glob.glob(os.path.join(directory, "*.profraw")) + glob.glob(os.path.join(directory, "tests", "*.profraw"))
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


def jacoco(meta, directory):
    """JVM servers run with the JaCoCo agent (JavaLaunchPlan).

    The agent dumped the library classes it saw under classes/, so the report
    reads the exact class files the server ran. A line counts as hit when
    JaCoCo covered at least one of its instructions; JaCoCo keeps no hit
    counts.
    """
    # The agent sends each test's data to the PerTestCoverage listener, which writes it under tests/.
    data = sorted(glob.glob(os.path.join(directory, "tests", "*.exec")))
    classes = os.path.join(directory, "classes")
    if not data or not os.path.isdir(classes):
        return None
    xml_path = os.path.join(directory, "jacoco.xml")
    run(["java", "-jar", os.environ["TESTSERVER_JACOCO_CLI"], "report", *data,
         "--classfiles", classes, "--xml", xml_path])
    return jacoco_xml_to_lcov(xml_path, meta["sources"])


def jacoco_xml_to_lcov(xml_path, sources):
    """lcov for each JaCoCo <sourcefile> found under one of the source roots."""
    import xml.etree.ElementTree as ElementTree
    out = []
    for package in ElementTree.parse(xml_path).getroot().iter("package"):
        for sourcefile in package.findall("sourcefile"):
            relative = os.path.join(package.get("name"), sourcefile.get("name"))
            path = next((os.path.join(root, relative) for root in sources
                         if os.path.isfile(os.path.join(root, relative))), None)
            if path is None:
                continue
            out.append("SF:%s\n" % path)
            for line in sourcefile.findall("line"):
                out.append("DA:%s,%d\n" % (line.get("nr"), 1 if int(line.get("ci")) > 0 else 0))
            out.append("end_of_record\n")
    return "".join(out)


def coverage_py(meta, directory):
    """Python servers run under coverage.py (PythonLaunchPlan).

    Each server process wrote its own .coverage.* data file; the lcov report
    names files relative to the library directory.
    """
    directory = os.path.abspath(directory)
    if not glob.glob(os.path.join(directory, ".coverage.*")):
        return None
    coverage = [meta["python"], "-m", "coverage"]
    rcfile = "--rcfile=" + os.path.join(directory, "coveragerc")
    run(coverage + ["combine", rcfile])
    lcov_path = os.path.join(directory, "coverage.lcov")
    run(coverage + ["lcov", rcfile, "-o", lcov_path], cwd=meta["library"])
    with open(lcov_path) as f:
        return f.read()
# c8 turns Node's raw V8 coverage into lcov.
C8_VERSION = "10.1.3"


def v8(meta, directory):
    """Node.js servers run with NODE_V8_COVERAGE (NodeLaunchPlan).

    c8 maps the compiled JavaScript back to the TypeScript sources through the
    inline source maps the build emits. Only the library's own packages under
    modules/ are kept, not the server or its dependencies.
    """
    data = os.path.join(directory, "v8")
    if not glob.glob(os.path.join(data, "*.json")):
        return None
    report = os.path.join(directory, "lcov")
    run(["npx", "--yes", "c8@" + C8_VERSION, "report", "--temp-directory", data,
         "--reporter=lcov", "--report-dir", report, "--all=false"], cwd=meta["root"])
    with open(os.path.join(report, "lcov.info")) as f:
        lcov = f.read()
    modules = os.path.join(os.path.realpath(meta["root"]), "modules") + "/"

    def library_file(path):
        path = os.path.realpath(os.path.join(meta["root"], path))
        return path.startswith(modules) and "/node_modules/" not in path

    return keep_files(lcov, library_file)


def gcov(meta, directory):
    """C servers built with --coverage (CLaunchPlan).

    The server wrote each object's .gcda file under gcda/ followed by the
    object's absolute path (GCOV_PREFIX). gcov reads it beside a copy of the
    object's .gcno file from the build tree. A header's lines are counted in
    every object that includes it, so their counts are summed.
    """
    prefix = os.path.join(directory, "gcda")
    counts = {}
    # os.walk, not glob: the build tree is test-server/.build, which glob skips.
    found = [os.path.join(parent, name) for parent, _, names in os.walk(prefix)
             for name in names if name.endswith(".gcda")]
    for data in found:
        notes = data[len(prefix):-len(".gcda")] + ".gcno"
        if not os.path.exists(notes):
            continue
        shutil.copyfile(notes, data[:-len(".gcda")] + ".gcno")
        out = run(["gcov", "--json-format", "--stdout", data], capture_output=True, text=True,
                  cwd=os.path.dirname(data)).stdout
        for line in out.splitlines():
            if not line.startswith("{"):
                continue
            report = json.loads(line)
            for source in report["files"]:
                path = os.path.realpath(os.path.join(report["current_working_directory"], source["file"]))
                hits = counts.setdefault(path, {})
                for record in source["lines"]:
                    hits[record["line_number"]] = hits.get(record["line_number"], 0) + record["count"]
    out = []
    for path in sorted(counts):
        out.append("SF:%s\n" % path)
        out.extend("DA:%d,%d\n" % (number, hits) for number, hits in sorted(counts[path].items()))
        out.append("end_of_record\n")
    return "".join(out)


def gocover(meta, directory):
    """Go servers built with -cover (GoLaunchPlan).

    The server wrote its counters under gocover/ (GOCOVERDIR) when it exited.
    covdata turns them into a text profile, which names each file by its
    import path; meta["modules"] maps each module path to its directory.
    """
    counters = os.path.join(directory, "gocover")
    if not glob.glob(os.path.join(counters, "covcounters.*")):
        return None
    profile = os.path.join(directory, "gocover.txt")
    run(["go", "tool", "covdata", "textfmt", "-i=" + counters, "-o", profile])
    with open(profile) as f:
        return go_profile_to_lcov(f.read(), meta["modules"])


def go_profile_to_lcov(profile, modules):
    """lcov from a Go text profile: `<import path>:<l>.<c>,<l>.<c> <statements> <count>`.

    A block counts on every line it spans, except a last line it only reaches
    the indentation of (the line of the closing brace). A line in several
    blocks keeps the highest count.
    """
    by_length = sorted(modules, key=len, reverse=True)
    counts = {}
    sources = {}
    for record in profile.splitlines():
        if not record or record.startswith("mode:"):
            continue
        location, _, count = record.rsplit(" ", 2)
        name, span = location.rsplit(":", 1)
        module = next((m for m in by_length if name.startswith(m + "/")), None)
        if module is None:
            continue
        path = modules[module] + name[len(module):]
        start, end = span.split(",")
        start_line = int(start.split(".")[0])
        end_line, end_column = (int(part) for part in end.split("."))
        if end_line > start_line:
            if path not in sources:
                try:
                    with open(path) as f:
                        sources[path] = f.read().splitlines()
                except OSError:
                    sources[path] = []
            lines = sources[path]
            if end_line <= len(lines) and not lines[end_line - 1][:end_column - 1].strip():
                end_line -= 1
        hits = counts.setdefault(path, {})
        for number in range(start_line, end_line + 1):
            hits[number] = max(hits.get(number, 0), int(count))
    return lines_to_lcov(counts)


def dotnet_coverage(meta, directory):
    """.NET servers run under dotnet-coverage collect (DotnetLaunchPlan).

    Each server run wrote a .coverage file when it exited; dotnet-coverage
    merges them into one Cobertura report.
    """
    data = sorted(glob.glob(os.path.join(directory, "*.coverage")))
    if not data:
        return None
    xml_path = os.path.join(directory, "coverage.cobertura.xml")
    run([meta["dotnet_coverage"], "merge", *data, "--output", xml_path, "--output-format", "cobertura"])
    return cobertura_to_lcov(xml_path)


def cobertura_to_lcov(xml_path):
    """lcov from a Cobertura report. A line listed by several classes (a
    method's compiler-generated classes) keeps the highest count."""
    import xml.etree.ElementTree as ElementTree
    root = ElementTree.parse(xml_path).getroot()
    bases = [source.text for source in root.iter("source") if source.text]
    counts = {}
    for cls in root.iter("class"):
        path = cls.get("filename")
        if not os.path.isabs(path):
            path = next((os.path.join(base, path) for base in bases
                         if os.path.exists(os.path.join(base, path))), path)
        hits = counts.setdefault(path, {})
        for line in cls.iter("line"):
            number = int(line.get("number"))
            hits[number] = max(hits.get(number, 0), int(line.get("hits")))
    return lines_to_lcov(counts)


def lines_to_lcov(counts):
    """lcov from {path: {line number: hits}}."""
    out = []
    for path in sorted(counts):
        if not counts[path]:
            continue
        out.append("SF:%s\n" % path)
        out.extend("DA:%d,%d\n" % (number, hits) for number, hits in sorted(counts[path].items()))
        out.append("end_of_record\n")
    return "".join(out)


def keep_files(lcov, keep):
    """The lcov records whose SF path satisfies keep(path)."""
    out, keeping = [], False
    for line in lcov.splitlines(keepends=True):
        if line.startswith("SF:"):
            keeping = keep(line[3:].strip())
        if keeping:
            out.append(line)
    return "".join(out)


CONVERTERS = {
    "llvm": llvm,
    "jacoco": jacoco,
    "coverage.py": coverage_py,
    "v8": v8,
    "gcov": gcov,
    "gocover": gocover,
    "dotnet-coverage": dotnet_coverage,
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
