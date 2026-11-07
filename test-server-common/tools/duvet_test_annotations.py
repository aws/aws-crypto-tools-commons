#!/usr/bin/env python3
"""Copy the duvet test annotations of the shared Tests into one language's duvet.

The shared Tests carry `//= ... //= type=test //# ...` annotations. A language
should get credit for an annotation only if the test holding it runs for that
language. A dry run (orchestrator `dryRun=true languages=<lang>`) writes the
feature-gate log, where every test that reached a server call has a
`would-run` line. This script keeps the annotations of those tests and writes
them to one file the language's duvet config reads as a test source.

An annotation is dropped when:
  - its test does not reach a server call for the language (a feature-gate or
    other skip), or
  - its test calls KnownBugGate.gateDeclared with a bug id the language lists
    in its bug-config.json, or
  - with --spec-root, its quote is not in that section of the language's spec
    (duvet fails the whole report on such a quote).

An annotation in a helper method counts for the tests in the same file that
call that helper. An annotation outside any method, or one that is not
`type=test`, is an error.

Usage:
  duvet_test_annotations.py --gate-log build/test-results/feature-gate-log.jsonl \
      --tests-dir tests/src/test/java --out <dir>/esdk.java \
      [--bug-config <language repo>/esdk/test-server/bug-config.json] \
      [--spec-root <language repo>/esdk] [--prefix specification/=spec/]
"""

import argparse
import json
import re
import sys
from pathlib import Path

TEST_ANNOTATIONS = {"@Test", "@ParameterizedTest", "@RepeatedTest", "@TestFactory",
                    "@TestTemplate", "@Property", "@Example"}
META_KEYS = {"type", "reason", "tracking-issue", "feature", "level", "format"}
METHOD = re.compile(
    r"^\s*(?:(?:public|protected|private|static|final|synchronized|abstract|default)\s+)*"
    r"(?:<[^>]*>\s+)?[\w.$<>\[\],? ]+?\s+(\w+)\s*\(")
NOT_METHOD = re.compile(r"^\s*(?:return|new|if|for|while|switch|catch|throw|else|do|try|case)\b")
GATE_DECLARED = re.compile(r'gateDeclared\(\s*"([^"]+)"')
CALL = re.compile(r"\b(\w+)\s*\(")
GATE_ID_SEGMENT = re.compile(r"\[(\w[\w-]*):([^\]]*)\]")
TEST_SEGMENTS = {"method", "test-template", "test-factory", "property", "example"}


class Block:
    def __init__(self, path, line, target):
        self.path, self.line, self.target = path, line, target
        self.meta, self.quote = [], []

    def kind(self):
        for key, value in self.meta:
            if key == "type":
                return value
        return "implementation"

    def render(self, prefixes):
        target = self.target
        for old, new in prefixes:
            if target.startswith(old):
                target = new + target[len(old):]
                break
        lines = [f"//= {target}"]
        lines += [f"//= {key}={value}" for key, value in self.meta]
        lines += [f"//#{q}" for q in self.quote]
        return "\n".join(lines)


class Method:
    def __init__(self, name, is_test, start):
        self.name, self.is_test, self.start = name, is_test, start
        self.end = None
        self.body = []  # code with literals blanked, for calls
        self.raw = []   # source lines, for bug ids


def strip_code(line):
    """The line without string and char literals and // comments, for brace counting."""
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])'", "''", line)
    return line.split("//", 1)[0]


def parse_java(path):
    """Return (methods, blocks) for one Java file."""
    text = path.read_text(encoding="utf-8").splitlines()
    methods, blocks, stack = [], [], []
    depth, pending, block = 0, [], None
    in_block_comment = False
    for number, raw in enumerate(text, 1):
        stripped = raw.strip()
        if stripped.startswith("//="):
            body = stripped[3:].strip()
            key, eq, value = body.partition("=")
            if block is not None and eq and key in META_KEYS and " " not in key:
                block.meta.append((key, value))
            else:
                block = Block(path, number, body)
                blocks.append(block)
            continue
        if stripped.startswith("//#"):
            if block is None:
                raise SystemExit(f"{path}:{number}: //# line with no //= target above it")
            block.quote.append(stripped[3:])
            continue
        block = None
        code = raw
        if in_block_comment:
            if "*/" not in code:
                continue
            code = code.split("*/", 1)[1]
            in_block_comment = False
        code = re.sub(r"/\*.*?\*/", "", code)
        if "/*" in code:
            code, in_block_comment = code.split("/*", 1)[0], True
        code = strip_code(code)
        if not code.strip():
            continue
        if code.strip().startswith("@"):
            pending.append(code.strip().split("(")[0])
        match = METHOD.match(code)
        if match and not NOT_METHOD.match(code) and "=" not in code.split("(")[0] \
                and not code.rstrip().endswith(";"):
            method = Method(match.group(1), bool(TEST_ANNOTATIONS & set(pending)), number)
            methods.append(method)
            # [method, depth its body opens at, whether its body has opened]
            stack.append([method, depth + 1, False])
            pending = []
        elif not code.strip().startswith("@"):
            pending = []
        for entry in stack:
            entry[0].body.append(code)
            entry[0].raw.append(raw)
        for char in code:
            if char == "{":
                depth += 1
                for entry in stack:
                    if not entry[2] and depth == entry[1]:
                        entry[2] = True
            elif char == "}":
                depth -= 1
                while stack and stack[-1][2] and depth < stack[-1][1]:
                    stack.pop()[0].end = number
            elif char == ";":
                # A statement ended before the match opened a body: not a method.
                while stack and not stack[-1][2] and depth + 1 == stack[-1][1]:
                    methods.remove(stack.pop()[0])
    return methods, blocks


def enclosing(methods, line):
    inside = [m for m in methods if m.start <= line and (m.end is None or line <= m.end)]
    return max(inside, key=lambda m: m.start) if inside else None


def calls(method, names):
    found = set()
    for code in method.body:
        found |= {name for name in CALL.findall(code) if name in names}
    return found - {method.name}


def tests_reaching(method, methods):
    """The test methods in this file that are, or call (transitively), `method`."""
    if method.is_test:
        return {method.name}
    by_name = {}
    for m in methods:
        by_name.setdefault(m.name, []).append(m)
    names = set(by_name)
    reached, frontier = {method.name}, {method.name}
    while frontier:
        callers = {m.name for m in methods if calls(m, names) & frontier} - reached
        reached |= callers
        frontier = callers
    return {name for name in reached if any(m.is_test for m in by_name[name])}


def declared_bugs(test_name, methods):
    """Every gateDeclared bug id in the test and the helpers it calls."""
    by_name = {}
    for m in methods:
        by_name.setdefault(m.name, []).append(m)
    names, ids = set(by_name), set()
    seen, frontier = set(), {test_name}
    while frontier:
        name = frontier.pop()
        seen.add(name)
        for m in by_name.get(name, []):
            ids |= set(GATE_DECLARED.findall("\n".join(m.raw)))
            frontier |= calls(m, names) - seen
    return ids


def would_run(gate_log):
    """(class simple name, test method name) of every test with a would-run line."""
    keys = set()
    for raw in gate_log.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        entry = json.loads(raw)
        if entry.get("result") != "would-run":
            continue
        cls = method = None
        for kind, value in GATE_ID_SEGMENT.findall(entry["id"]):
            if kind in ("class", "nested-class") and cls is None:
                cls = value.rsplit(".", 1)[-1].split("$", 1)[0]
            elif kind in TEST_SEGMENTS and method is None:
                method = value.split("(", 1)[0]
        if cls and method:
            keys.add((cls, method))
    return keys


def slug(heading, seen):
    """duvet's section id: lowercase, each run of other characters a `-`, repeats numbered."""
    base = re.sub(r"[^a-z0-9]+", "-", heading.strip().lower()).strip("-")
    count = seen.get(base, 0)
    seen[base] = count + 1
    return base if count == 0 else f"{base}-{count}"


def normalize(text):
    """Letters and digits only: duvet accepts a quote that differs in spacing or punctuation."""
    return re.sub(r"[^A-Za-z0-9]", "", text)


def spec_sections(spec_file):
    sections, seen, current = {}, {}, None
    for line in spec_file.read_text(encoding="utf-8").splitlines():
        heading = re.match(r"^#{1,6}\s+(.*)$", line)
        if heading:
            current = slug(heading.group(1), seen)
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return {name: normalize(" ".join(lines)) for name, lines in sections.items()}


def quote_problem(block, spec_root, prefixes, cache):
    target = block.render(prefixes).splitlines()[0][len("//= "):]
    file_part, _, section = target.partition("#")
    spec_file = spec_root / file_part
    if not spec_file.is_file():
        return f"no spec file {file_part}"
    if spec_file not in cache:
        cache[spec_file] = spec_sections(spec_file)
    text = cache[spec_file].get(section)
    if text is None:
        return f"no section #{section} in {file_part}"
    if normalize(" ".join(block.quote)) not in text:
        return f"quote not in {file_part}#{section}"
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--gate-log", type=Path, required=True)
    parser.add_argument("--tests-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--bug-config", type=Path)
    parser.add_argument("--spec-root", type=Path)
    parser.add_argument("--prefix", action="append", default=[],
                        help="rewrite a spec path prefix, as FROM=TO")
    args = parser.parse_args(argv)

    prefixes = [tuple(p.split("=", 1)) for p in args.prefix]
    running = would_run(args.gate_log)
    bugs = set()
    if args.bug_config and args.bug_config.is_file():
        bugs = set(json.loads(args.bug_config.read_text(encoding="utf-8")))

    kept, dropped, errors, cache = [], [], [], {}
    for path in sorted(args.tests_dir.rglob("*.java")):
        methods, blocks = parse_java(path)
        for block in blocks:
            where = f"{path}:{block.line}"
            if block.kind() != "test":
                errors.append(f"{where}: shared Tests may only hold type=test annotations")
                continue
            method = enclosing(methods, block.line)
            if method is None:
                errors.append(f"{where}: annotation is not inside a method")
                continue
            tests = tests_reaching(method, methods)
            if not tests:
                errors.append(f"{where}: no test in {path.name} calls {method.name}")
                continue
            ran = sorted(t for t in tests if (path.stem, t) in running)
            clean = [t for t in ran if not (declared_bugs(t, methods) & bugs)]
            if not ran:
                dropped.append((where, "test does not run for this language"))
            elif not clean:
                dropped.append((where, "known bug declared in bug-config.json"))
            elif args.spec_root and (problem := quote_problem(block, args.spec_root, prefixes, cache)):
                dropped.append((where, problem))
            else:
                kept.append((block, path.stem, clean[0]))

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    out = ["// Generated by test-server-common/tools/duvet_test_annotations.py from a",
           "// test-server dry run. Each block is a shared Test that runs for this language."]
    for block, cls, test in kept:
        out += ["", f"// {cls}#{test}", block.render(prefixes)]
    args.out.write_text("\n".join(out) + "\n", encoding="utf-8")

    print(f"kept {len(kept)} annotations, dropped {len(dropped)}; wrote {args.out}")
    for where, reason in dropped:
        print(f"  dropped {where}: {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
