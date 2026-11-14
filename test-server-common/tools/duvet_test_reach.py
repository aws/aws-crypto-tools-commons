#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Check that the test behind each duvet test annotation runs the code it cites.

duvet pairs a `type=test` annotation with an implementation annotation by their
quote alone. This check uses per-test line coverage to ask, for one language,
whether some run of the test that holds the test annotation hit a line of the
code under an implementation annotation for the same requirement.

The code under an implementation annotation (its region) is the one statement
or block that starts on the first code line after the annotation:
  - a statement ends at a `;` or `,` outside any bracket it opened;
  - a block (`fn`, `if`, `match`, ...) ends at its closing `}`, unless an
    `else` follows it;
  - the region also ends where the enclosing block closes, and just before the
    next annotation.
Annotations with only blank lines or comments between them share one region,
the one after the last of them. Only lines the
coverage tool can count (`DA` lines in --lcov) are checked; a region with none
is NO REGION. `implication`, `exception` and `todo` annotations have no code to
run and are skipped.

A test annotation belongs to the test function or JUnit method around it. One
in a helper belongs to every test in the same file that calls the helper. A
parameterized test's annotation covers every one of its cases.

For each test annotation and each language the result is one of:
  OK                       a run of the test hit a line in a region
  TEST NEVER REACHES CODE  runs of the test hit no line in any region
  NOT RUN                  every run of the test was skipped, or none was recorded
  NO REGION                no implementation annotation for it has countable code
  NO COVERAGE              the language has no per-test coverage file

Usage:
  duvet_test_reach.py --language rust --library esdk \\
      --repository aws/aws-crypto-tools-rust --repo-root language-repo \\
      --source esdk/src --local-tests esdk/tests \\
      --commons-root . --shared-tests esdk/test-server/tests/src/test/java \\
      --coverage per-test-coverage/rust.jsonl --lcov coverage/rust.lcov \\
      [--changed changed.json] [--prefix specification/=spec/] \\
      --out reach/esdk-rust.json
"""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import duvet_test_annotations as shared_tests

OK, NEVER, NOT_RUN, NO_REGION, NO_COVERAGE = (
    "ok", "never-reaches", "not-run", "no-region", "no-coverage")
LABELS = {OK: "OK", NEVER: "TEST NEVER REACHES CODE", NOT_RUN: "NOT RUN",
          NO_REGION: "NO REGION", NO_COVERAGE: "NO COVERAGE"}
SKIPPED_TYPES = {"implication", "exception", "todo"}
EXTENSIONS = {".rs", ".java", ".go", ".cs", ".c", ".h", ".cpp", ".hpp", ".cc",
              ".ts", ".js", ".dfy"}
RUST_TEST_ATTRIBUTE = re.compile(r"#\[\s*(?:[\w:]+::)?(?:test|rstest|test_case)\b")
RUST_FN = re.compile(r"\bfn\s+(\w+)")
RUST_MOD = re.compile(r"\bmod\s+(\w+)\s*\{")
OPEN, CLOSE = "([{", ")]}"


# ---------- reading source ----------

def code_lines(text, java=False, block_comment_lines=None):
    """Each line with comments, strings and char literals turned into spaces.

    Line breaks are kept, so line numbers match the file. Rust lifetimes (`'a`)
    stay code. Nested Rust `/* */` comments, Rust raw strings and Java text
    blocks are handled; that is enough to count brackets. The 1-based number
    of every line inside a `/* */` comment is added to `block_comment_lines`.
    """
    out, i, n = list(text), 0, len(text)

    def blank(start, end):
        for k in range(start, min(end, n)):
            if out[k] != "\n":
                out[k] = " "
        return min(end, n)

    while i < n:
        c = text[i]
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = blank(i, n if end < 0 else end)
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                elif text.startswith("/*", j) and not java:
                    depth, j = depth + 1, j + 2
                else:
                    j += 1
            if block_comment_lines is not None:
                first = text.count("\n", 0, i) + 1
                block_comment_lines.update(range(first, first + text.count("\n", i, j) + 1))
            i = blank(i, j)
        elif java and text.startswith('"""', i):
            end = text.find('"""', i + 3)
            i = blank(i, n if end < 0 else end + 3)
        elif not java and (raw := re.match(r'b?r(#*)"', text[i:i + 260])) and \
                (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            close = '"' + raw.group(1)
            end = text.find(close, i + raw.end())
            i = blank(i, n if end < 0 else end + len(close))
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            i = blank(i, j + 1)
        elif c == "'" and text.startswith("\\", i + 1):
            end = text.find("'", i + 2)
            i = blank(i, n if end < 0 else end + 1)
        elif c == "'" and i + 2 < n and text[i + 2] == "'":
            i = blank(i, i + 3)
        else:  # code, including a Rust lifetime or label
            i += 1
    return "".join(out).split("\n")


class Annotation:
    """One `//=` block: target, meta lines and quote."""

    def __init__(self, path, line, target):
        self.path, self.line, self.end, self.target = path, line, line, target
        self.meta, self.quote = {}, []

    @property
    def kind(self):
        return self.meta.get("type", "implementation")

    def text(self):
        return " ".join(q.strip() for q in self.quote)


def annotation_stacks(raw_lines, rel_path):
    """Runs of `//=` and `//#` lines, which may be joined by bare `//` lines.

    Returns [(first line, last line, [Annotation])], with 1-based lines.
    """
    stacks, current, block = [], None, None
    for number, raw in enumerate(raw_lines, 1):
        s = raw.strip()
        if s.startswith(("//=", "//#")):
            if current is None:
                current = [number, number, []]
            if s.startswith("//="):
                body = s[3:].strip()
                key, eq, value = body.partition("=")
                if block is not None and eq and key in shared_tests.META_KEYS:
                    block.meta[key] = value
                else:
                    block = Annotation(rel_path, number, body)
                    current[2].append(block)
            elif block is None:
                raise SystemExit(f"{rel_path}:{number}: //# line with no //= target above it")
            else:
                block.quote.append(s[3:])
            block.end = current[1] = number
        elif current is not None and s != "//":
            stacks.append(tuple(current))
            current, block = None, None
    if current is not None:
        stacks.append(tuple(current))
    return stacks


def region_after(code, after, stops):
    """(first line, last line) of the statement or block after line `after`.

    `code` is the output of code_lines and `stops` maps the first line of
    every annotation stack to its last line. Returns None when the enclosing
    block ends before any statement does. The rule is the one in this module's
    docstring.
    """
    n, line = len(code), after + 1
    while line <= n and (line in stops or not code[line - 1].strip()):
        # A later stack with no code before it shares this stack's region.
        line = stops[line] + 1 if line in stops else line + 1
    if line > n or code[line - 1].lstrip()[:1] in CLOSE:
        return None
    first, depth, generics, closed_at = line, 0, 0, None

    def last_code(upto):
        while upto > first and not code[upto - 1].strip():
            upto -= 1
        return upto

    while line <= n:
        if line != first and line in stops:
            return first, closed_at or last_code(line - 1)
        text = code[line - 1]
        for col, c in enumerate(text):
            if closed_at is not None and not c.isspace():
                # A block closed; `else`, `.` or `?` continue the statement.
                if c in ";,":
                    return first, line
                if c in ".?" or re.match(r"else\b", text[col:]):
                    closed_at = None
                else:
                    return first, closed_at
            before = text[col - 1] if col else " "
            after_c = text[col + 1] if col + 1 < len(text) else " "
            if c in OPEN:
                depth += 1
            elif c in CLOSE:
                depth -= 1
                if depth < 0:  # the enclosing block closed
                    return first, line if text[:col].strip() else last_code(line - 1)
                if depth == 0 and c == "}":
                    closed_at = line
            # Type arguments like `HashMap<K, V>`: their commas end nothing.
            elif c == "<" and (before.isalnum() or before in "_:") and not after_c.isspace():
                generics += 1
            elif c == ">" and generics and not before.isspace() and before not in "-=":
                generics -= 1
            elif c in ";," and depth == 0 and not (c == "," and generics):
                return first, line
        line += 1
    return first, closed_at or last_code(n)


def normalize(text):
    return re.sub(r"[^A-Za-z0-9]", "", text)


def rewrite(target, prefixes):
    for old, new in prefixes:
        if target.startswith(old):
            return new + target[len(old):]
    return target

# ---------- implementation annotations ----------

class Implementation:
    def __init__(self, annotation, region, countable):
        self.annotation, self.region, self.countable = annotation, region, countable


def implementations(repo_root, sources, prefixes, countable_lines):
    """{target: [Implementation]} for every implementation annotation in `sources`."""
    by_target = defaultdict(list)
    for source in sources:
        for path in sorted((repo_root / source).rglob("*")):
            if path.suffix not in EXTENSIONS or not path.is_file():
                continue
            rel = path.relative_to(repo_root).as_posix()
            text = path.read_text(encoding="utf-8", errors="replace")
            stacks = annotation_stacks(text.splitlines(), rel)
            if not stacks:
                continue
            code = code_lines(text, java=path.suffix == ".java")
            stops = {first: last for first, last, _ in stacks}
            for _, last, blocks in stacks:
                region = region_after(code, last, stops)
                lines = set()
                if region:
                    lines = {line for line in range(region[0], region[1] + 1)
                             if line in countable_lines.get(rel, ())}
                for block in blocks:
                    block.target = rewrite(block.target, prefixes)
                    by_target[block.target].append(Implementation(block, region, sorted(lines)))
    return by_target


def matching(test_block, by_target):
    """Implementation annotations for the same requirement: same target, one quote inside the other."""
    quote = normalize(test_block.text())
    out = []
    for impl in by_target.get(test_block.target, []):
        other = normalize(impl.annotation.text())
        if quote and other and (quote in other or other in quote):
            out.append(impl)
    return out


# ---------- test annotations ----------

class TestAnnotation:
    def __init__(self, annotation, repository, source, tests):
        # tests: [(test name for display, matcher)], matcher(row) -> bool
        self.annotation, self.repository, self.source, self.tests = annotation, repository, source, tests


def rust_tests(repo_root, tests_dir, crate, repository, prefixes, errors):
    """Test annotations in Rust test files, each with the tests that hold it."""
    out = []
    for path in sorted((repo_root / tests_dir).rglob("*.rs")):
        rel = path.relative_to(repo_root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        stacks = annotation_stacks(text.splitlines(), rel)
        blocks = [b for _, _, bs in stacks for b in bs if b.kind == "test"]
        if not blocks:
            continue
        commented_out = set()
        code = code_lines(text, block_comment_lines=commented_out)
        functions = rust_functions(code)
        inner = path.relative_to(repo_root / tests_dir)
        binary = inner.parts[0] if len(inner.parts) > 1 else inner.stem
        for block in blocks:
            block.target = rewrite(block.target, prefixes)
            if block.line in commented_out:
                errors.append(f"{rel}:{block.line}: test annotation is in a /* */ comment, so no test runs it")
                continue
            holder = enclosing(functions, block.line) or function_after(functions, code, block.end)
            if holder is None:
                errors.append(f"{rel}:{block.line}: test annotation is not inside or above a function")
                continue
            names = reaching(holder, functions)
            if not names:
                errors.append(f"{rel}:{block.line}: no test in {path.name} calls {holder.name}")
                continue
            tests = []
            for f in functions:
                if f.name in names and f.is_test:
                    path_in_binary = "::".join(f.modules + [f.name])
                    ids = {f"{crate}::{binary}::{path_in_binary}", f"{binary}::{path_in_binary}",
                           f"{crate}::{path_in_binary}"}
                    tests.append((f"{binary}::{path_in_binary}", lambda row, ids=ids: rust_id(row) in ids))
            out.append(TestAnnotation(block, repository, "local", tests))
    return out


def rust_id(row):
    return re.sub(r"\s+", "::", row["test"].strip())


class Function:
    def __init__(self, name, is_test, start, modules):
        self.name, self.is_test, self.start, self.modules = name, is_test, start, modules
        self.end, self.body = None, []


def rust_functions(code):
    """Every `fn` with a body in one Rust file, with the `mod` path around it.

    `code` is the output of code_lines. A function is a test when a test
    attribute (`#[test]`, `#[tokio::test]`, `#[rstest]`, ...) sits above it.
    """
    functions, mods = [], []
    open_items = []  # [function or module name, brace depth inside its body]
    depth, test_attribute, pending = 0, False, None
    for number, text in enumerate(code, 1):
        s = text.strip()
        if RUST_TEST_ATTRIBUTE.search(s):
            test_attribute = True
        fn, mod = RUST_FN.search(text), RUST_MOD.search(text)
        if fn:
            pending = Function(fn.group(1), test_attribute, number, list(mods))
            test_attribute = False
        elif mod:
            pending = mod.group(1)
        elif s and not s.startswith("#"):
            test_attribute = False
        for c in text:
            if c == "{":
                depth += 1
                if pending is not None:
                    open_items.append([pending, depth])
                    if isinstance(pending, Function):
                        functions.append(pending)
                    else:
                        mods.append(pending)
                    pending = None
            elif c == "}":
                if open_items and open_items[-1][1] == depth:
                    item = open_items.pop()[0]
                    if isinstance(item, Function):
                        item.end = number
                    else:
                        mods.pop()
                depth -= 1
            elif c == ";" and isinstance(pending, Function):
                pending = None  # a declaration with no body
    for f in functions:
        f.body = code[f.start - 1:f.end]
    return functions


def function_after(functions, code, line):
    """The function that starts right after `line`, past attributes and comments."""
    for f in functions:
        between = code[line:f.start - 1]
        if f.start > line and all(not s.strip() or s.strip().startswith("#") for s in between):
            return f
    return None


def enclosing(functions, line):
    inside = [f for f in functions if f.start <= line and f.end is not None and line <= f.end]
    return max(inside, key=lambda f: f.start) if inside else None


def reaching(holder, functions):
    """Names of the test functions that are, or call (transitively), `holder`."""
    names = {f.name for f in functions}
    reached, frontier = {holder.name}, {holder.name}
    while frontier:
        callers = set()
        for f in functions:
            if f.name in reached:
                continue
            called = {name for text in f.body for name in shared_tests.CALL.findall(text)} & names
            if called & frontier:
                callers.add(f.name)
        reached |= callers
        frontier = callers
    return {f.name for f in functions if f.name in reached and f.is_test}


def java_tests(commons_root, tests_dir, prefixes, errors):
    """Test annotations in the shared JUnit Tests, each with the methods that hold it."""
    out = []
    for path in sorted((commons_root / tests_dir).rglob("*.java")):
        methods, blocks = shared_tests.parse_java(path)
        rel = path.relative_to(commons_root).as_posix()
        for raw in blocks:
            if raw.kind() != "test":
                continue
            block = Annotation(rel, raw.line, rewrite(raw.target, prefixes))
            block.meta, block.quote = dict(raw.meta), raw.quote
            method = shared_tests.enclosing(methods, raw.line)
            if method is None:
                errors.append(f"{rel}:{raw.line}: test annotation is not inside a method")
                continue
            names = shared_tests.tests_reaching(method, methods)
            if not names:
                errors.append(f"{rel}:{raw.line}: no test in {path.name} calls {method.name}")
                continue
            tests = [(f"{path.stem}#{name}", lambda row, cls=path.stem, name=name: java_match(row, cls, name))
                     for name in sorted(names)]
            out.append(TestAnnotation(block, "aws/aws-crypto-tools-commons", "test-server", tests))
    return out


def java_match(row, cls, method):
    """Whether a coverage row is a run of JUnit method `cls#method`.

    The class part may be fully qualified. The method comes from the row's
    JUnit unique ID (`junit_id`), else from a display name that starts with
    `method(`. A parameterized case's display name does not name its method,
    so such a row needs `junit_id`.
    """
    row_class, _, display = row["test"].partition("#")
    if row_class.rsplit(".", 1)[-1].split("$", 1)[0] != cls:
        return False
    for kind, value in shared_tests.GATE_ID_SEGMENT.findall(row.get("junit_id", "")):
        if kind in shared_tests.TEST_SEGMENTS:
            return value.split("(", 1)[0] == method
    return display == method or display.startswith(method + "(")


# ---------- coverage ----------

def read_coverage(path):
    rows = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            row = json.loads(raw)
            row["files"] = {f: set(lines) for f, lines in row.get("files", {}).items()}
            rows.append(row)
    return rows


def read_lcov(paths):
    """{path: {line}} of every line an lcov file counts (its DA lines)."""
    lines, current = defaultdict(set), None
    for path in paths:
        for raw in path.read_text(encoding="utf-8").splitlines():
            if raw.startswith("SF:"):
                current = raw[3:]
            elif raw.startswith("DA:") and current is not None:
                lines[current].add(int(raw[3:].split(",", 1)[0]))
    return lines


def changed_lines(repo, base):
    """{path: {line}} of lines added or changed since `base` in a git checkout."""
    diff = subprocess.run(["git", "-C", str(repo), "diff", "-U0", "--no-color", f"{base}...HEAD"],
                          check=True, capture_output=True, text=True).stdout
    out, path = defaultdict(set), None
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            path = raw[6:] if raw.startswith("+++ b/") else None
        elif raw.startswith("@@") and path:
            m = re.search(r"\+(\d+)(?:,(\d+))?", raw)
            start, count = int(m.group(1)), int(m.group(2) or 1)
            out[path].update(range(start, start + count))
    return out


def touched(annotation, changed):
    lines = changed.get(annotation.path, ())
    return any(line in lines for line in range(annotation.line, annotation.end + 1))


# ---------- the check ----------

def check(test, impls, rows, have_coverage):
    """One finding for a test annotation in one language."""
    regions = [i for i in impls if i.countable]
    finding = {"implementations": [{
        "path": i.annotation.path, "line": i.annotation.line,
        "region": list(i.region) if i.region else None, "lines": i.countable} for i in impls]}
    if not any(i.region for i in impls):
        finding["state"] = NO_REGION
        finding["detail"] = "no code under any implementation annotation"
        return finding
    if not have_coverage:
        finding["state"] = NO_COVERAGE
        return finding
    if not regions:
        finding["state"] = NO_REGION
        finding["detail"] = "no line coverage can count under any implementation annotation"
        return finding
    runs = [(name, row) for name, matcher in test.tests for row in rows
            if row.get("source") == test.source and matcher(row)]
    finding["runs"] = [{"test": row["test"], "status": row.get("status"), "reason": row.get("reason")}
                       for _, row in runs]
    ran = [row for _, row in runs if row.get("status") != "skipped"]
    if not ran:
        finding["state"] = NOT_RUN
        reasons = sorted({row.get("reason") or "skipped" for _, row in runs})
        finding["detail"] = ", ".join(reasons) if runs else "no run of the test was recorded"
        return finding
    for row in ran:
        for i in regions:
            if set(i.countable) & row["files"].get(i.annotation.path, set()):
                finding["state"] = OK
                finding["hit"] = {"test": row["test"], "path": i.annotation.path, "line": i.annotation.line}
                return finding
    finding["state"] = NEVER
    return finding


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--language", required=True)
    parser.add_argument("--library", required=True, help="esdk, mpl, dbesdk or primitives")
    parser.add_argument("--repository", required=True, help="owner/name of the library repository")
    parser.add_argument("--repo-root", type=Path, required=True, help="checkout of the library repository")
    parser.add_argument("--commit", default="", help="library repository commit, for links")
    parser.add_argument("--source", action="append", default=[],
                        help="directory under --repo-root holding implementation annotations")
    parser.add_argument("--local-tests", action="append", default=[],
                        help="directory under --repo-root holding Rust test files")
    parser.add_argument("--crate", default="", help="package name of the --local-tests crate")
    parser.add_argument("--commons-root", type=Path, help="checkout of aws-crypto-tools-commons")
    parser.add_argument("--commons-commit", default="")
    parser.add_argument("--shared-tests", action="append", default=[],
                        help="directory under --commons-root holding the shared JUnit Tests")
    parser.add_argument("--coverage", type=Path, action="append", default=[],
                        help="per-test coverage JSON lines; missing files are fine")
    parser.add_argument("--lcov", type=Path, action="append", default=[],
                        help="lcov whose DA lines are the lines coverage can count")
    parser.add_argument("--changed-since", action="append", default=[],
                        help="REPO=BASE: check only annotations changed in that checkout since BASE,"
                             " where REPO is 'library' or 'commons'")
    parser.add_argument("--prefix", action="append", default=[], help="rewrite a spec path prefix, as FROM=TO")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    prefixes = [tuple(p.split("=", 1)) for p in args.prefix]
    coverage_files = [p for p in args.coverage if p.is_file()]
    rows = [r for p in coverage_files for r in read_coverage(p) if r.get("language", args.language) == args.language]
    countable = read_lcov([p for p in args.lcov if p.is_file()])
    if not countable:
        # Without lcov, a line counts if any run hit it.
        for row in rows:
            for path, lines in row["files"].items():
                countable.setdefault(path, set()).update(lines)

    errors = []
    by_target = implementations(args.repo_root, args.source, prefixes, countable)
    tests = []
    for directory in args.local_tests:
        tests += rust_tests(args.repo_root, directory, args.crate, args.repository, prefixes, errors)
    for directory in args.shared_tests:
        tests += java_tests(args.commons_root, directory, prefixes, errors)

    changed = None
    for spec in args.changed_since:
        which, _, base = spec.partition("=")
        root = args.repo_root if which == "library" else args.commons_root
        changed = changed or {}
        changed[which] = changed_lines(root, base)

    commits = {args.repository: args.commit, "aws/aws-crypto-tools-commons": args.commons_commit}
    findings, skipped = [], defaultdict(int)
    for test in tests:
        impls_all = matching(test.annotation, by_target)
        impls = [i for i in impls_all if i.annotation.kind not in SKIPPED_TYPES]
        if not impls:
            skipped["implication or exception only" if impls_all else "no implementation annotation"] += 1
            continue
        if changed is not None:
            test_side = "commons" if test.source == "test-server" else "library"
            if not (touched(test.annotation, changed.get(test_side, {})) or
                    any(touched(i.annotation, changed.get("library", {})) for i in impls)):
                continue
        finding = check(test, impls, rows, bool(coverage_files))
        finding.update({
            "requirement": {"target": test.annotation.target, "quote": test.annotation.text()},
            "test_annotation": {"repository": test.repository, "commit": commits.get(test.repository, ""),
                                "path": test.annotation.path, "line": test.annotation.line,
                                "end": test.annotation.end},
            "source": test.source,
            "tests": [name for name, _ in test.tests],
        })
        findings.append(finding)

    counts = {state: sum(f["state"] == state for f in findings) for state in LABELS}
    report = {"language": args.language, "library": args.library, "repository": args.repository,
              "commit": args.commit, "commons_commit": args.commons_commit,
              "mode": "changed" if changed is not None else "all",
              "coverage": bool(coverage_files), "counts": counts, "skipped": dict(skipped),
              "errors": errors, "findings": findings}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")

    print(f"## duvet test reach: {args.library} ({args.language}, {report['mode']} annotations)\n")
    print(" | ".join(f"{LABELS[s]}: {n}" for s, n in counts.items()))
    for reason, n in sorted(skipped.items()):
        print(f"\nnot checked, {reason}: {n}")
    for f in findings:
        if f["state"] in (NEVER, NO_REGION):
            t = f["test_annotation"]
            print(f"\n- {LABELS[f['state']]}: {t['path']}:{t['line']} {f['requirement']['target']}"
                  f" ({', '.join(f['tests'])})")
    for e in errors:
        print(f"\nerror: {e}")
    return 1 if counts[NEVER] or errors else 0


if __name__ == "__main__":
    sys.exit(main())
