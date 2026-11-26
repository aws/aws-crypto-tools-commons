#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""What CI found on the lines a pull request changes, in one findings file, and the PR comments for it.

Usage:
  pr_findings.py build <owner/repo#N> [--run <id>]... [--exclude <glob>]... [--fuzz-count N]
                       [--dashboard <url>] [--out findings.json] [--summary <markdown file>]
      Reads the pull request's diff and files and the artifacts of its CI runs, and writes findings.json.
      Without --run it reads every workflow run on the head commit, and for each artifact name the
      newest run that uploaded it. --exclude leaves files out of the line and branch checks, the way
      the coverage checks leave out test server code.
  pr_findings.py post <findings.json> [--off <kind>]... [--dry-run]
      Puts each finding that sits on a line of the diff on that line, as a review comment from the
      token's account. A finding that changed has its comment edited. A comment whose finding is gone
      gets a "Fixed" line, and its thread is resolved. A token without contents: write cannot resolve
      a thread, so then the comment is hidden as resolved. A comment is marked fixed only when the run
      read its check's results for that comment's project. A comment of a kind turned off with --off,
      or of a check this script no longer has, is hidden as outdated. Each review that posted comments
      gets its summary line set to the newest counts and dashboard link.
  pr_findings.py line <owner/repo#N> <file>:<line> [--run <id>]...
      Prints everything CI found on one line, changed or not.

The token comes from GH_TOKEN or GITHUB_TOKEN, or else from `gh auth token`.

findings.json:
  {"schema": 1, "repository", "pr", "title", "head", "base_ref", "ci_commit", "runs": [<run id>],
   "dashboard": <the PR's page on the dashboard>, "read": {<check>: [<what was read>]},
   "missing": [<what had no results>], "checked": {<check>: [<project folder>]}, "findings": [<finding>]}
  checked lists, for each check that comments on lines, the project folders whose results the run read,
  and "" when the check covers the whole pull request.
  A finding:
  {"key", "check", "kind", "level", "file", "line", "end_line", "side", "title", "what", "why": [<sentence>],
   "fix", "evidence": {...}, "patch": [<old line>, <new line>] or null, "rerun": [<shell command>],
   "suggestion": <replacement for the line> or null, "links": {"dashboard", "ci", "ci_name"}}
  level is "block" for a gap in testing, which a required check fails on too, and "warn" for a note
  for the reviewer, on a change to the public API. file and line are null for a finding about no one
  line, such as a failed test server case. end_line is the last line of a finding on several lines,
  such as the code a duvet test never reaches, or else null. side is "RIGHT" for a line of the head
  commit and "LEFT" for a removed line. key stays the same for the same finding after a push, so its
  comment is found again. links.ci is the check run the finding comes from, named ci_name, or else
  the workflow run.
  The rerun commands use $RUST and $COMMONS for checkouts of the library repository and of commons.
"""

import argparse
import collections
import fnmatch
import hashlib
import io
import json
import os
import posixpath
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

COMMONS = "aws/aws-crypto-tools-commons"
DASHBOARD = "https://aws.github.io/aws-crypto-tools-commons/"
MARKER = "<!-- pr-findings "
CACHE = Path(os.environ.get("PR_FINDINGS_CACHE", Path.home() / ".cache" / "pr-findings"))
FAILED_CHECK = {"failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale"}
BAD_MUTANT = {"survived", "not_covered"}
CODE_FILE = re.compile(r"\.(rs|java|kt|go|cs|py|ts|js|mjs|c|h|cc|cpp|hpp|dfy)$")
# A line in a test or an example that no test runs is not a gap in testing.
TEST_FILE = re.compile(r"(^|/)(tests?|benches|examples)/|_tests?\.rs$|Tests?\.java$|\.test\.js$")
# The check runs that only sum up the others, and the job that runs this script.
SUMMARY_CHECKS = re.compile(r"^pr-ci-all-required$|^PR findings\b", re.I)
# The checks that findings come from. A findings comment of another check is from an older version of
# this script, and is hidden.
CHECKS = {"checks", "lines", "branches", "mutation", "reach", "servers", "fuzz", "conformance", "api"}
# The names of the check runs that some checks read their results from; {folder} is the project's folder.
CHECK_RUNS = {
    "lines": r"^Patch coverage \({folder}\)( /|$)",
    "branches": r"^Patch coverage \({folder}\)( /|$)",
    "mutation": r"^Mutation testing \({folder}\)( /|$)",
    "reach": r"^duvet test reach \({folder}\)( /|$)",
    "api": r"^API types$",
}


# ---------- GitHub ----------

def token():
    found = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if found:
        return found
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        sys.exit("no token: set GH_TOKEN or GITHUB_TOKEN, or log in with `gh auth login`")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Lets a 302 through as a response, so an artifact's storage URL is fetched without the token."""

    def redirect_request(self, *args, **kwargs):
        return None


class GitHub:
    def __init__(self, auth, api="https://api.github.com"):
        self.auth, self.api = auth, api
        self.plain = urllib.request.build_opener(NoRedirect)

    def request(self, method, path, body=None, accept="application/vnd.github+json", raw=False):
        url = path if path.startswith("https://") else f"{self.api}/{path}"
        data = None if body is None else json.dumps(body).encode()
        headers = {"Accept": accept, "Authorization": f"Bearer {self.auth}", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "pr-findings"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        # GitHub answers 502 now and then on large lists, so a server error is tried again.
        for attempt in range(4):
            try:
                with self.plain.open(urllib.request.Request(url, data=data, method=method, headers=headers),
                                     timeout=180) as res:
                    content = res.read()
                break
            except urllib.error.HTTPError as e:
                if e.code == 302 and raw:
                    with urllib.request.urlopen(e.headers["Location"], timeout=600) as res:
                        return res.read()
                if e.code >= 500 and attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"GitHub {e.code} for {method} {path}: {e.read().decode()[:300]}") from None
            except urllib.error.URLError:
                if attempt == 3:
                    raise
                time.sleep(2 ** attempt)
        if raw:
            return content
        return json.loads(content) if content else None

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def pages(self, path, key=None, limit=30):
        out = []
        for page in range(1, limit + 1):
            got = self.get(f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}")
            items = got[key] if key else got
            out += items
            if len(items) < 100:
                break
        return out

    def raw_file(self, repo, path, ref):
        quoted = urllib.parse.quote(path)
        return self.get(f"repos/{repo}/contents/{quoted}?ref={ref}", accept="application/vnd.github.raw",
                        raw=True).decode("utf-8", "replace")

    def graphql(self, query, **variables):
        got = self.request("POST", "graphql", {"query": query, "variables": variables})
        if got.get("errors"):
            raise RuntimeError(f"GitHub GraphQL: {got['errors']}")
        return got["data"]


def artifact_zip(gh, repo, art):
    """The artifact's zip, kept on disk by id, because an artifact never changes."""
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / f"{repo.replace('/', '_')}-{art['id']}.zip"
    if not path.exists():
        path.write_bytes(gh.get(f"repos/{repo}/actions/artifacts/{art['id']}/zip", raw=True))
    return zipfile.ZipFile(io.BytesIO(path.read_bytes()))


def parse_pr(text):
    m = (re.search(r"github\.com/([^/\s]+/[^/\s]+)/pull/(\d+)", text)
         or re.match(r"^(?:([\w.-]+/[\w.-]+))?#(\d+)$", text.strip()))
    if not m:
        sys.exit(f"not a pull request: {text}")
    return m[1] or COMMONS, int(m[2])


# ---------- reading ----------

def diff_rows(patch):
    """[(kind, old line, new line, text)] for one file's patch. kind is hunk, add, del or ctx."""
    rows, old, new = [], 0, 0
    lines = (patch or "").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for line in lines:
        hunk = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if hunk:
            old, new = int(hunk[1]), int(hunk[2])
            rows.append(("hunk", None, None, line))
        elif line.startswith("\\"):
            continue
        elif line.startswith("+"):
            rows.append(("add", None, new, line[1:]))
            new += 1
        elif line.startswith("-"):
            rows.append(("del", old, None, line[1:]))
            old += 1
        else:
            rows.append(("ctx", old, new, line[1:]))
            old += 1
            new += 1
    return rows


def parse_lcov(text, lines, branches, wanted):
    """Adds the DA hits into lines[file][line] and the BRDA counts into branches[file][line][id], for wanted files."""
    current = None
    for row in text.splitlines():
        if row.startswith("SF:"):
            current = row[3:].strip() if row[3:].strip() in wanted else None
        elif current and row.startswith("DA:"):
            n, hits = row[3:].split(",")[:2]
            got = lines[current]
            got[int(n)] = max(got.get(int(n), 0), int(hits))
        elif current and row.startswith("BRDA:"):
            n, block, branch, taken = row[5:].split(",")
            got = branches[current].setdefault(int(n), {})
            key = f"{block},{branch}"
            got[key] = max(got.get(key, 0), 0 if taken.strip() == "-" else int(taken))
        elif row.startswith("end_of_record"):
            current = None


def parse_per_test(text, repo, wanted, tests):
    """Adds each test run that hit a wanted file to tests: {"names": [...], "at": {file: {line: [index]}}}."""
    for line in text.splitlines():
        if not line.strip():
            continue
        t = json.loads(line)
        if t.get("repository") and t["repository"] != repo:
            continue
        index = None
        for file, hits in (t.get("files") or {}).items():
            if file not in wanted:
                continue
            if index is None:
                index = len(tests["names"])
                tests["names"].append({"name": t["test"], "source": t.get("source"), "status": t.get("status"),
                                       "language": t.get("language")})
            for n in hits:
                tests["at"].setdefault(file, {}).setdefault(n, []).append(index)


TESTCASE = re.compile(r"<testcase\b([^>]*?)(?:/>|>(.*?)</testcase>)", re.S)


def unxml(s):
    return (s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&apos;", "'")
            .replace("&amp;", "&"))


def junit(text):
    """(number of cases, [(class, name, message)] of the failed ones) in one JUnit XML file."""
    count, failed = 0, []
    for attrs, body in TESTCASE.findall(text):
        count += 1
        bad = re.search(r"<(?:failure|error)\b([^>]*)", body or "")
        if bad:
            name = re.search(r'\bname="([^"]*)"', attrs)
            cls = re.search(r'\bclassname="([^"]*)"', attrs)
            msg = re.search(r'\bmessage="([^"]*)"', bad[1])
            failed.append((unxml(cls[1]) if cls else "", unxml(name[1]) if name else "",
                           unxml(msg[1])[:400] if msg else ""))
    return count, failed


def annotations(text):
    """The duvet annotations in a file: [{start, end, target, type, quote, code}].

    code is the first line after the block that is neither blank nor a comment. duvet ties an annotation
    to that line, and annotations with only comments between them share it.
    """
    lines, out, i = text.split("\n"), [], 0
    while i < len(lines):
        head = re.match(r"^\s*//=\s*(\S+)\s*$", lines[i])
        if not head:
            i += 1
            continue
        block = {"start": i + 1, "target": head[1], "type": "implementation", "quote": []}
        j = i + 1
        while j < len(lines):
            meta = re.match(r"^\s*//=\s*(type|reason|tracking-issue)=(.*)$", lines[j])
            quote = re.match(r"^\s*//#(?: (.*)|$)", lines[j])
            if meta:
                if meta[1] == "type":
                    block["type"] = meta[2].strip()
            elif quote:
                block["quote"].append(quote[1] or "")
            else:
                break
            j += 1
        block["end"] = j
        k = j
        while k < len(lines) and re.match(r"^\s*(//.*)?$", lines[k]):
            k += 1
        block["code"] = k + 1 if k < len(lines) else None
        block["quote"] = " ".join(block["quote"]).strip()
        out.append(block)
        i = j
    return out


def ranges(numbers):
    """[3, 4, 5, 9] -> "3-5, 9"."""
    out, start, prev = [], None, None
    for n in sorted(set(numbers)):
        if start is None:
            start = prev = n
        elif n == prev + 1:
            prev = n
        else:
            out.append(f"{start}" if start == prev else f"{start}-{prev}")
            start = prev = n
    if start is not None:
        out.append(f"{start}" if start == prev else f"{start}-{prev}")
    return ", ".join(out)


def plural(n, one, many=None):
    return f"{n} {one if n == 1 else (many or one + 's')}"


MD_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")


def heading_anchors(text):
    """The anchors GitHub gives a markdown file's headings: "## Encrypted Data Key" -> "encrypted-data-key"."""
    seen, out = collections.Counter(), set()
    for m in re.finditer(r"^#{1,6}[ \t]+(.+?)[ \t#]*$", text, re.M):
        anchor = re.sub(r"[^\w\- ]", "", m[1].strip().lower()).replace(" ", "-")
        out.add(f"{anchor}-{seen[anchor]}" if seen[anchor] else anchor)
        seen[anchor] += 1
    return out


# ---------- mutants ----------

BOUNDARY = {("<", "<="), ("<=", "<"), (">", ">="), (">=", ">")}
FLIPS = {("==", "!="), ("!=", "==")}
LOGIC = {("&&", "||"), ("||", "&&")}


def mutant_change(m):
    """(kind of change, from, to) from a mutant's description, like ("binary", ">=", ">")."""
    d = m.get("description", "")
    if m.get("kind") == "binary":
        got = re.match(r"replace (\S+) with (\S+)$", d)
        return ("binary", got[1], got[2]) if got else ("binary", None, None)
    if m.get("kind") == "condition":
        got = re.match(r"replace the condition with (\w+)$", d)
        return ("condition", None, got[1] if got else None)
    if m.get("kind") == "unary":
        got = re.match(r"delete (\S+)$", d)
        return ("unary", got[1] if got else None, None)
    if m.get("kind") == "fn_value":
        got = re.match(r"replace the body of (\S+) with (.+)$", d)
        return ("fn_value", got[1] if got else m.get("function"), got[2].replace(" :: ", "::") if got else None)
    if m.get("kind") == "match_arm":
        got = re.match(r"delete the match arm (.+)$", d)
        return ("match_arm", got[1] if got else None, None)
    if m.get("kind") == "skip_call":
        got = re.match(r"skip the call to (\S+)$", d)
        return ("skip_call", got[1] if got else None, None)
    return (m.get("kind"), None, None)


def operands(text, column, op):
    """The two sides of the operator that starts at 1-based column in text, or None.

    Each side ends where its expression ends on this line: at a bracket it did not open, at `,` `;` `{`,
    at `&&` or `||`, or at the start of the line's keyword (if, while, return, let x =).
    """
    i = column - 1
    if text[i:i + len(op)] != op:
        return None
    depth, j = 0, i - 1
    while j >= 0:
        c = text[j]
        if c in ")]":
            depth += 1
        elif c in "([":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and (c in ",;{}" or text[j - 1:j + 1] in ("&&", "||")
                             or (c == "=" and text[j - 1:j] not in "=!<>" and text[j + 1:j + 2] != "=")):
            break
        j -= 1
    left = text[j + 1:i].strip()
    left = re.sub(r"^(?:if|while|return|match|else if|let\s+\w+\s*=)\s+", "", left).strip()
    depth, k = 0, i + len(op)
    while k < len(text):
        c = text[k]
        if c in "([":
            depth += 1
        elif c in ")]":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and (c in ",;{}" or text[k:k + 2] in ("&&", "||")):
            break
        k += 1
    right = text[i + len(op):k].strip()
    return (left, right) if left and right else None


def mutated_line(text, m):
    """The line with the mutant applied, for a mutant that swaps or deletes one operator, else None."""
    change, frm, to = mutant_change(m)
    i = m.get("column", 0) - 1
    if change == "binary" and frm and to and text[i:i + len(frm)] == frm:
        return text[:i] + to + text[i + len(frm):]
    if change == "unary" and frm and text[i:i + len(frm)] == frm:
        return text[:i] + text[i + len(frm):]
    return None


def mutant_words(m, text, n_tests):
    """(what happened, why no test caught it, the fix) for a surviving mutant, in plain words."""
    change, frm, to = mutant_change(m)
    tests = "every test" if not n_tests else "the one test" if n_tests == 1 else f"all {n_tests} tests"
    passes = f"still passes {tests}"
    if change == "binary":
        what = f"Changing `{frm}` to `{to}` {passes}."
        sides = operands(text or "", m.get("column", 0), frm or "")
        if (frm, to) in BOUNDARY:
            if sides:
                return (what, f"They differ only when `{sides[0]}` equals `{sides[1]}`, and no test checks that.",
                        f"Add a test where `{sides[0]}` equals `{sides[1]}`.")
            return (what, "They differ only when both sides are equal, and no test checks that.",
                    "Add a test where both sides are equal.")
        if (frm, to) in FLIPS:
            return (what, "No test depends on this comparison.",
                    "Add a test that checks what happens on each side of it.")
        if (frm, to) in LOGIC:
            return (what, "They differ only when one side is true and the other false, and no test checks that.",
                    "Add a test where one side is true and the other is false.")
        return (what, "No test checks this value.", "Add a test that checks this value.")
    if change == "condition":
        other = "false" if to == "true" else "true"
        return (f"Replacing the condition with `{to}` {passes}.", f"No test checks the {other} case.",
                f"Add a test where this condition is {other}, and check the result.")
    if change == "unary":
        return (f"Deleting the `{frm}` {passes}.", "No test depends on it.",
                "Add a test whose result changes without it.")
    if change == "fn_value":
        return (f"Replacing the body of `{frm}` with `{to}` {passes}.", f"No test checks what `{frm}` returns.",
                f"Add a test that checks what `{frm}` returns.")
    if change == "match_arm":
        return (f"Deleting the match arm `{frm}` {passes}.",
                "No test reaches this arm, or the other arms give the same result.",
                "Add a test that reaches this arm and checks its result.")
    if change == "skip_call":
        return (f"Skipping the call to `{frm}` {passes}.", f"No test notices when `{frm}` is not called.",
                f"Add a test that fails when `{frm}` is not called.")
    return (f"The mutant `{m.get('description')}` {passes}.", "No test notices this change.",
            "Add a test whose result changes with it.")


# ---------- branches ----------

def leaf_conditions(text):
    """The conditions of an if or while on this line, left to right, split at && and || at any depth."""
    got = re.search(r"\b(?:if|while)\s+(.*?)\s*\{?\s*$", text)
    if not got:
        return None
    expr, out, depth, start, i = got[1], [], 0, 0, 0
    while i < len(expr):
        c = expr[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        if expr[i:i + 2] in ("&&", "||"):
            out.append(expr[start:i])
            start, i = i + 2, i + 2
            continue
        i += 1
    out.append(expr[start:])
    leaves = []
    for part in out:
        # A part can carry the brackets of a group around it: `(a && b)` splits into `(a` and `b)`.
        part = part.strip()
        while part.startswith("(") and part.count("(") > part.count(")"):
            part = part[1:].strip()
        while part.endswith(")") and part.count(")") > part.count("("):
            part = part[:-1].strip()
        if part:
            leaves.append(part)
    return leaves


def branch_words(text, ids):
    """Which side of which condition no test takes, from the line's BRDA counts.

    llvm-cov writes two counts per condition, the true side first, with branch numbers 2k and 2k+1.
    """
    missed = [k for k, taken in sorted(ids.items(), key=lambda kv: [int(x) for x in kv[0].split(",")]) if not taken]
    leaves = leaf_conditions(text or "")
    blocks = sorted({int(k.split(",")[0]) for k in ids})
    out = []
    for k in missed:
        block, branch = (int(x) for x in k.split(","))
        side = "true" if branch % 2 == 0 else "false"
        if leaves and len(leaves) == len(blocks):
            out.append(f"No test makes `{leaves[blocks.index(block)]}` {side}.")
        else:
            out.append(f"No test takes branch {branch + 1} of {len(ids)} on this line.")
    return out


# ---------- the public API ----------

def api_diff(base, head):
    """What changed between two rust-api.json files: APIs added and removed, and options added, removed or
    taking another type."""
    before = {(a["lib"], a["id"]): a for a in (base or {}).get("apis", [])}
    after = {(a["lib"], a["id"]): a for a in (head or {}).get("apis", [])}
    out = {"added": [], "removed": [], "options_added": [], "options_removed": [], "options_changed": []}
    for key, a in after.items():
        b = before.get(key)
        if not b:
            out["added"].append(a)
        old = {o["name"]: o for o in (b or {}).get("options", [])}
        for o in a.get("options", []):
            was = old.pop(o["name"], None)
            row = {"api": a, "option": o, "was": was}
            if b and not was:
                out["options_added"].append(row)
            elif was and (was.get("takes") != o.get("takes") or was.get("set_takes") != o.get("set_takes")):
                out["options_changed"].append(row)
        if b:
            out["options_removed"] += [{"api": b, "option": o, "was": o} for o in old.values()]
    out["removed"] = [b for key, b in before.items() if key not in after]
    return out


def type_rows(types, api, option):
    """The types-rust.json rows of one option: each held type and the call it needs."""
    entry = next((a for a in (types or {}).get("apis", []) if a["lib"] == api["lib"] and a["id"] == api["id"]), None)
    found = entry and next((o for o in entry["options"] if o["name"] == option["name"]), None)
    return (found["key"], (types.get("rows") or {}).get(found["key"], [])) if found else (None, [])


def option_words(types, rules, api, option):
    """Sentences about how callers pass an option: the call counts, the types that need more than one call,
    and the rules it breaks."""
    key, rows = type_rows(types, api, option)
    if not rows:
        return []
    n = collections.Counter("none" if r.get("calls") is None else min(r["calls"], 2) for r in rows)
    out = [f"Of {plural(len(rows), 'type')} a caller may hold, {n[0]} pass as is, {n[1]} need one call, "
           f"{n[2]} need more, and {n['none']} have no fix."]
    many = [r for r in rows if r.get("calls") is not None and r["calls"] >= 2]
    if many:
        shown = "; ".join(f"`{r['type']}`: `{r['code']}`" for r in many[:3])
        out.append(f"More than one call: {shown}.")
    rule = (rules or {}).get("rules", {}).get(key)
    if rule:
        bad = sorted({r["kind"] for r in rows if r.get("calls") == 0 and r.get("kind") in rule.get("refuse", [])})
        if bad:
            out.append(f"It takes {', '.join(bad)} as is, but the rule says: {rule.get('why', '')}")
    return out


# ---------- the pull request ----------

class PR:
    """A pull request, its diff, and everything its CI runs uploaded."""

    def __init__(self, gh, repo, n, runs=None, excludes=(), fuzz_count=None):
        self.gh, self.repo, self.n, self.excludes, self.fuzz_count = gh, repo, n, list(excludes), fuzz_count
        self.pr = gh.get(f"repos/{repo}/pulls/{n}")
        self.head, self.base_ref = self.pr["head"]["sha"], self.pr["base"]["ref"]
        files = gh.pages(f"repos/{repo}/pulls/{n}/files")
        self.files = [{"file": f["filename"], "status": f["status"], "rows": diff_rows(f.get("patch")),
                       "previous": f.get("previous_filename")} for f in files]
        self.rows = {f["file"]: f["rows"] for f in self.files}
        self.wanted = set(self.rows)
        latest = {}
        for c in gh.pages(f"repos/{repo}/commits/{self.head}/check-runs", "check_runs"):
            if c["name"] not in latest or c["id"] > latest[c["name"]]["id"]:
                latest[c["name"]] = c
        self.checks = list(latest.values())
        if runs:
            self.runs = [gh.get(f"repos/{repo}/actions/runs/{r}") for r in runs]
        else:
            self.runs = gh.pages(f"repos/{repo}/actions/runs?head_sha={self.head}", "workflow_runs")
        self.texts, self.base_texts = {}, {}
        self.read, self.missing, self.errors, self.ci_commit = collections.defaultdict(list), [], [], None
        # For each check, the project folders whose results were read.
        self.checked = collections.defaultdict(set)
        self.local, self.server = collections.defaultdict(dict), collections.defaultdict(dict)
        self.branches = collections.defaultdict(dict)
        self.mutants = collections.defaultdict(lambda: collections.defaultdict(list))
        self.tests = {"names": [], "at": {}}
        self.reach, self.servers, self.fuzz, self.conformance = [], {}, {}, []
        self.api = {}
        self.blocks = {}
        self._spec, self.spec_files = "unread", {}
        self._load()

    # ----- loading -----
    def _merge_base(self):
        try:
            got = self.gh.get(f"repos/{self.repo}/compare/{self.pr['base']['sha']}...{self.head}")
            return got["merge_base_commit"]["sha"]
        except RuntimeError:
            return self.pr["base"]["sha"]

    def text(self, file):
        if file not in self.texts:
            try:
                self.texts[file] = self.gh.raw_file(self.repo, file, self.head)
            except RuntimeError:
                self.texts[file] = None
        return self.texts[file]

    def base_text(self, file):
        if file not in self.base_texts:
            try:
                self.base_texts[file] = self.gh.raw_file(self.repo, file, self.merge_base)
            except RuntimeError:
                self.base_texts[file] = None
        return self.base_texts[file]

    def artifacts(self, pattern, whole=False):
        """For each artifact name that matches, every artifact of that name from the newest run attempt that has one.

        A run can upload several artifacts under one name, one per job, and all of them are its results.
        With whole, each artifact is a whole report, such as one crate's mutation results, and only the
        newest one of each name counts; an older one is from a job that ran again.
        """
        by_name = collections.defaultdict(list)
        for a in self._arts:
            if re.search(pattern, a["name"]):
                by_name[a["name"]].append(a)
        out = []
        for arts in by_name.values():
            # A run keeps the artifacts of its earlier attempts, and GitHub may no longer serve them. A rerun
            # of some jobs uploads only theirs, so each name comes from the newest attempt that uploaded it.
            newest = max(arts, key=lambda a: a["created_at"])
            out += [newest] if whole else [a for a in arts if (a["run"], a["attempt"]) == (newest["run"], newest["attempt"])]
        return out

    def _attempt_starts(self, run):
        """When each attempt of a run started, the first attempt first."""
        n = run.get("run_attempt") or 1
        if n == 1:
            return [run.get("run_started_at") or ""]
        return [self.gh.get(f"repos/{self.repo}/actions/runs/{run['id']}/attempts/{k}")["run_started_at"]
                for k in range(1, n + 1)]

    def _load(self):
        self.merge_base = self._merge_base()
        self._arts = []
        for r in self.runs:
            starts = self._attempt_starts(r)
            for a in self.gh.pages(f"repos/{self.repo}/actions/runs/{r['id']}/artifacts", "artifacts"):
                if not a["expired"]:
                    attempt = sum(s <= a["created_at"] for s in starts)
                    self._arts.append({**a, "run": r["id"], "attempt": attempt})
        for f in self.files:
            if CODE_FILE.search(f["file"]) and f["status"] != "removed" and self.text(f["file"]) is not None:
                self.blocks[f["file"]] = annotations(self.texts[f["file"]])
        self._read_reach()
        self._read_mutants()
        self._read_coverage()
        self._read_servers()
        self._read_conformance()
        self._read_api()

    def zip(self, art):
        try:
            return artifact_zip(self.gh, self.repo, art)
        except RuntimeError as e:
            self.errors.append(f"{art['name']}: {e}")
            return None

    def _seen(self, commit):
        self.ci_commit = self.ci_commit or commit

    def _read_reach(self):
        for art in self.artifacts(r"^duvet-test-reach-", whole=True):
            z = self.zip(art)
            if z is None:
                continue
            name = next((x for x in z.namelist() if x.endswith(".json")), None)
            if not name:
                continue
            report = json.loads(z.read(name))
            self._seen(report.get("commit"))
            self.read["duvet test reach"].append(f"{report['library']} ({plural(len(report['findings']), 'annotation')})")
            self.checked["reach"].add(artifact_folder(art["name"]))
            for i, f in enumerate(report["findings"]):
                for imp in f.get("implementations") or []:
                    if imp.get("region"):
                        # The per-test coverage of this file is needed to say where the test went.
                        self.wanted.add(imp["path"])
                        self.reach.append({"finding": f"{art['name']}:{i}", "path": imp["path"],
                                           "from": imp["region"][0], "to": imp["region"][1], "state": f["state"],
                                           "requirement": f["requirement"], "test": f["test_annotation"],
                                           "runs": f.get("runs") or [], "detail": f.get("detail"),
                                           "library": report["library"]})

    def _read_mutants(self):
        for art in self.artifacts(r"^mutation-results-", whole=True):
            z = self.zip(art)
            if z is None:
                continue
            name = next((x for x in z.namelist() if x.endswith("results.json")), None)
            if not name:
                continue
            res = json.loads(z.read(name))
            self._seen(res["summary"].get("commit"))
            self.read["mutation"].append(f"{res['summary'].get('library')} ({plural(len(res['mutants']), 'mutant')})")
            self.checked["mutation"].add(artifact_folder(art["name"]))
            for m in res["mutants"]:
                if m["file"] in self.wanted and m["status"] != "not_sampled":
                    self.mutants[m["file"]][m["line"]].append(m)

    def _read_coverage(self):
        for art in self.artifacts(r"^local-coverage-"):
            z = self.zip(art)
            if z is None:
                continue
            self.read["local coverage"].append(art["name"][len("local-coverage-"):])
            for name in z.namelist():
                if name.endswith(".lcov"):
                    parse_lcov(z.read(name).decode(), self.local, self.branches, self.wanted)
                    self.checked["lines"].add(artifact_folder(art["name"]))
                    self.checked["branches"].add(artifact_folder(art["name"]))
        for art in self.artifacts(r"^per-test-coverage-", whole=True):
            z = self.zip(art)
            if z is None:
                continue
            for name in z.namelist():
                if name.endswith(".jsonl"):
                    parse_per_test(z.read(name).decode(), self.repo, self.wanted, self.tests)

    def _read_servers(self):
        for kind, pattern, into in (("test servers", r"-test-server-reports$", self.servers),
                                    ("fuzz", r"-test-server-fuzz-reports$", self.fuzz)):
            for art in self.artifacts(pattern):
                product = re.sub(r"-test-server(-fuzz)?-reports$", "", art["name"])
                z = self.zip(art)
                if z is None:
                    continue
                names = z.namelist()
                got = into.setdefault(product, {"product": product, "cases": 0, "failed": [], "run": art["run"]})
                for name in [x for x in names if re.search(r"test-results/.*TEST-[^/]*\.xml$", x)]:
                    count, failed = junit(z.read(name).decode(errors="replace"))
                    got["cases"] += count
                    got["failed"] += failed
                if into is self.fuzz:
                    continue
                # Only the regular runs count toward coverage: a random example is not a test someone wrote.
                for name in [x for x in names if re.search(r"(^|/)coverage/[^/]+\.json$", x)]:
                    meta, lcov = json.loads(z.read(name)), name[:-5] + ".lcov"
                    if meta.get("repository") == self.repo and lcov in names:
                        self._seen(meta.get("commit"))
                        parse_lcov(z.read(lcov).decode(), self.server, self.branches, self.wanted)
                for name in [x for x in names if re.search(r"per-test-coverage/[^/]+\.jsonl$", x)]:
                    parse_per_test(z.read(name).decode(), self.repo, self.wanted, self.tests)
            for product, got in into.items():
                self.read[kind].append(f"{product} ({plural(got['cases'], 'case')})")

    def _read_conformance(self):
        for art in self.artifacts(r"^smithy-conformance-", whole=True):
            z = self.zip(art)
            if z is None:
                continue
            names = z.namelist()
            md = next((z.read(x).decode() for x in names if x.endswith("report.md")), "")
            findings = next((json.loads(z.read(x)) for x in names if x.endswith("findings.json")), [])
            result = re.search(r"result: \*\*(\w+)\*\*", md)
            crate = art["name"][len("smithy-conformance-"):]
            self.read["smithy conformance"].append(f"{crate} {result[1] if result else '?'}")
            self.conformance.append({"crate": crate, "result": result[1] if result else None,
                                     "open": [f for f in findings if f.get("status") not in ("accepted", "deferred")]})

    def _read_api(self):
        """rust-api.json and types-rust.json at the head commit, and rust-api.json at the merge base."""
        for name, part in (("api-types-rust", "head"), ("api-types-rust-base", "base")):
            for art in self.artifacts(f"^{name}$", whole=True):
                z = self.zip(art)
                if z is None:
                    continue
                for file in z.namelist():
                    for want in ("rust-api.json", "types-rust.json", "expectations.json"):
                        if file.endswith(want):
                            self.api[f"{part}:{want}"] = json.loads(z.read(file))
        if self.api:
            self.read["API"].append("head" + (" and base" if "base:rust-api.json" in self.api else ""))
        if "head:rust-api.json" in self.api and "base:rust-api.json" in self.api:
            self.checked["api"].add("")

    # ----- looking up -----
    def changed(self, file):
        """The lines this PR adds to file."""
        return [new for kind, _, new, _ in self.rows.get(file, []) if kind == "add"]

    def span_end(self, file, start, end):
        """The last line of start..end that one comment can cover: a comment on several lines stops where
        the diff does, since GitHub takes only lines of one hunk."""
        last = start
        while last < end and self.commentable(file, last + 1):
            last += 1
        return last

    def commentable(self, file, line, side="RIGHT"):
        for kind, old, new, _ in self.rows.get(file, []):
            if side == "RIGHT" and kind in ("add", "ctx") and new == line:
                return True
            if side == "LEFT" and kind in ("del", "ctx") and old == line:
                return True
        return False

    def line_text(self, file, line):
        text = self.text(file)
        if text is None:
            return None
        lines = text.split("\n")
        return lines[line - 1] if 0 < line <= len(lines) else None

    def run_state(self, file, line):
        """"run", "not-run", or "none" when no coverage tool counts the line, like a comment."""
        hits = [src[file][line] for src in (self.local, self.server) if file in src and line in src[file]]
        return "none" if not hits else "run" if max(hits) > 0 else "not-run"

    def tests_at(self, file, line):
        return [self.tests["names"][i] for i in self.tests["at"].get(file, {}).get(line, [])]

    def excluded(self, file):
        return TEST_FILE.search(file) or any(fnmatch.fnmatch(file, g) for g in self.excludes)

    def dashboard(self, base, file=None, line=None):
        """The PR Review tab on this PR, at file:line; base may carry a query of its own, such as ?ref=."""
        url = urllib.parse.urlsplit(base)
        query = dict(urllib.parse.parse_qsl(url.query))
        query["pr"] = f"{self.repo}#{self.n}"
        if file:
            query["line"] = f"{file}:{line}"
        return urllib.parse.urlunsplit(url._replace(query=urllib.parse.urlencode(query, safe="/:"), fragment="pr-review"))

    def ci_url(self, check=None):
        if check:
            return check.get("html_url")
        return self.runs[0]["html_url"] if self.runs else self.pr["html_url"] + "/checks"

    def check_of(self, f):
        """The check run a finding comes from, the failed one if one failed, or None."""
        pattern = CHECK_RUNS.get(f["check"])
        if not pattern:
            return None
        folder = re.escape(f["evidence"].get("library") or folder_of(f["file"] or ""))
        found = [c for c in self.checks if re.search(pattern.format(folder=folder), c["name"])]
        return max(found, key=lambda c: (c.get("conclusion") in FAILED_CHECK, c["id"]), default=None)

    # ----- the spec -----
    def spec_source(self):
        """(owner/repo, ref) of the spec that the annotations cite as spec/, from scripts/spec-source.json."""
        if self._spec == "unread":
            self._spec = None
            try:
                src = json.loads(self.gh.raw_file(self.repo, "scripts/spec-source.json", self.head))["spec"]
                got = re.match(r"https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$", src["url"])
                self._spec = (got[1], src["ref"]) if got else None
            except (RuntimeError, ValueError, KeyError, TypeError):
                pass
        return self._spec

    def spec_file(self, path):
        if path not in self.spec_files:
            try:
                self.spec_files[path] = self.gh.raw_file(self._spec[0], path, self._spec[1])
            except RuntimeError:
                self.spec_files[path] = None
        return self.spec_files[path]

    def spec_text(self, quote, target):
        """A requirement's quote, with each link in it made a GitHub link that opens its part of the spec.

        A quote links to other spec files by relative paths, which go nowhere from a PR comment. A link
        whose file or heading this cannot find is left as its text.
        """
        source = target.split("#")[0]

        def fix(m):
            text, link = m[1], m[2]
            if re.match(r"https?://", link):
                return m[0]
            path, _, anchor = link.partition("#")
            if not source.startswith("spec/") or not self.spec_source():
                return text
            here = source[len("spec/"):]
            path = posixpath.normpath(posixpath.join(posixpath.dirname(here), path)) if path else here
            body = None if path.startswith("..") else self.spec_file(path)
            if body is None or (anchor and anchor not in heading_anchors(body)):
                return text
            repo, ref = self._spec
            return f"[{text}](https://github.com/{repo}/blob/{ref}/{path}{'#' + anchor if anchor else ''})"

        return MD_LINK.sub(fix, quote)


# ---------- finding ----------

def finding(check, kind, level, title, what, file=None, line=None, side="RIGHT", why=(), fix=None, evidence=None,
            rerun=(), patch=None, suggestion=None, key_parts=(), end_line=None):
    # The comments of a check missing from CHECKS are hidden as outdated.
    assert check in CHECKS, check
    parts = [check, kind, file or ""] + [str(p) for p in key_parts]
    return {"key": hashlib.sha256("\u0000".join(parts).encode()).hexdigest()[:16], "check": check, "kind": kind,
            "level": level, "file": file, "line": line, "end_line": end_line if end_line and end_line > line else None,
            "side": side, "title": title, "what": what,
            "why": [w for w in why if w], "fix": fix, "evidence": evidence or {}, "patch": patch,
            "rerun": list(rerun), "suggestion": suggestion, "links": {}}


def project_of(file):
    return file.split("/")[0]


# The C++ shim has its own coverage, but its files are in the ESDK's folder.
FOLDERS = {"cpp-shim": "esdk/shims/aws-esdk-cpp"}


def artifact_folder(name):
    """The folder of the project a per-project artifact is about: "duvet-test-reach-mpl-rust" -> "mpl"."""
    project = re.sub(r"^(local-coverage|mutation-results|duvet-test-reach)-|-rust$", "", name)
    return FOLDERS.get(project, project)


def folder_of(file):
    """The folder of the project file is in, the way artifact_folder names it."""
    return next((f for f in FOLDERS.values() if file.startswith(f + "/")), project_of(file))


def feature_flags(project):
    # The coverage checks build prim without its features, because they turn on FIPS.
    return "" if project == "prim" else " --all-features"


def coverage_rerun(pr, file):
    p = project_of(file)
    excludes = " ".join(f"'{g}'" for g in pr.excludes)
    flags = " ".join(f"--exclude '{g}'" for g in pr.excludes)
    return [f'cd "$RUST/{p}" && cargo +nightly llvm-cov{feature_flags(p)} --workspace --branch --lcov '
            f"--remap-path-prefix --output-path lcov.info && sed -i.bak 's|^SF:|SF:{p}/|' lcov.info",
            f'cd "$RUST" && diff-cover {p}/lcov.info --compare-branch origin/{pr.base_ref}'
            + (f" --exclude {excludes}" if excludes else ""),
            f'cd "$RUST" && python3 "$COMMONS/test-server-common/tools/branch_gate.py" --base origin/{pr.base_ref}'
            + (f" {flags}" if flags else "") + f" {p}/lcov.info"]


def server_rerun(product, cls, fuzz=None):
    env = f"TESTSERVER_FUZZ={fuzz[0]} TESTSERVER_FUZZ_SEED={fuzz[1]} " if fuzz else ""
    return [f'cd "$COMMONS" && {env}make -C {product}/test-server orchestrate '
            f'ORCHESTRATE_ARGS="languages=rust tests={cls} workingTreeOverlay.aws-crypto-tools-rust=$RUST"']


PRODUCT_DIRS = {"esdk": "esdk", "mpl": "mpl", "prim": "primitives", "primitives": "primitives", "dbesdk": "dbesdk"}


def build_findings(pr, dashboard=DASHBOARD):
    out = []
    out += check_findings(pr)
    out += line_findings(pr)
    out += mutant_findings(pr)
    out += reach_findings(pr)
    out += server_findings(pr)
    out += conformance_findings(pr)
    out += api_findings(pr)
    unrun = {(f["file"], f["line"]) for f in out if f["kind"] == "line-not-run"}
    out = [f for f in out if not (f["kind"] == "mutant-not-covered" and (f["file"], f["line"]) in unrun)]
    # Two findings can have the same key, such as two `//= type=implication` lines in one file.
    # Numbering them in line order keeps each key the same after a push that moves both.
    seen = collections.Counter()
    for f in sorted(out, key=lambda f: (f["file"] or "", f["line"] or 0)):
        seen[f["key"]] += 1
        if seen[f["key"]] > 1:
            f["key"] = hashlib.sha256(f"{f['key']}#{seen[f['key']]}".encode()).hexdigest()[:16]
    code = [f for f in pr.files if CODE_FILE.search(f["file"]) and not pr.excluded(f["file"]) and pr.changed(f["file"])]
    if code:
        if not (pr.local or pr.server):
            pr.missing.append("line coverage")
        if "mutation" not in pr.read:
            pr.missing.append("mutation results")
    if any(f["file"].endswith(".rs") and "/src/" in f["file"] and not pr.excluded(f["file"]) for f in code) \
            and not pr.api and pr.repo.endswith("/aws-crypto-tools-rust"):
        pr.missing.append("API types")
    for f in out:
        f["links"]["dashboard"] = pr.dashboard(dashboard, f["file"], f["line"])
        if not f["links"].get("ci"):
            check = pr.check_of(f)
            f["links"]["ci"] = check["html_url"] if check else pr.ci_url()
            f["links"]["ci_name"] = check["name"].split(" / ")[0] if check else None
    return out


def check_findings(pr):
    out = []
    for c in pr.checks:
        if c.get("conclusion") in FAILED_CHECK and not SUMMARY_CHECKS.search(c["name"]):
            f = finding("checks", "check-failed", "block", "Check failed", f"`{c['name']}` failed.",
                        key_parts=[c["name"]], evidence={"conclusion": c["conclusion"]})
            f["links"]["ci"], f["links"]["ci_name"] = c.get("html_url"), c["name"].split(" / ")[0]
            out.append(f)
    return out


def line_findings(pr):
    out = []
    if not (pr.local or pr.server):
        return out
    for f in pr.files:
        file = f["file"]
        if not CODE_FILE.search(file) or pr.excluded(file):
            continue
        for line in pr.changed(file):
            state = pr.run_state(file, line)
            text = pr.line_text(file, line) or ""
            if state == "not-run":
                # The tests that run a line just above are the ones to extend, for an agent that adds the test.
                above = next((n for n in range(line - 1, max(0, line - 12), -1) if pr.run_state(file, n) == "run"), None)
                tests = pr.tests_at(file, above) if above else []
                out.append(finding("lines", "line-not-run", "block", "No test runs this line", "No test runs this line.",
                                   file, line, fix="Add a test that runs this line, or remove it if nothing can.",
                                   evidence={"above": above, "tests_above": [t["name"] for t in tests[:10]]},
                                   rerun=coverage_rerun(pr, file), key_parts=[text.strip()]))
            elif state == "run":
                ids = pr.branches.get(file, {}).get(line, {})
                missed = [k for k, t in ids.items() if not t]
                if missed:
                    out.append(finding("branches", "branch-not-taken", "block", "Untested branch",
                                       " ".join(branch_words(text, ids)), file, line,
                                       fix="Add a test that takes the missing branch.",
                                       evidence={"branches": ids, "tests_count": len(pr.tests_at(file, line))},
                                       rerun=coverage_rerun(pr, file), key_parts=[text.strip()]))
    return out


def mutant_findings(pr):
    out = []
    for file, by_line in pr.mutants.items():
        for line, mutants in sorted(by_line.items()):
            text = pr.line_text(file, line)
            caught = sorted({m["killed_by"] for m in mutants if m.get("killed_by")})
            tests = pr.tests_at(file, line)
            for m in (m for m in mutants if m["status"] in BAD_MUTANT):
                n = m.get("tests_run") or len(tests)
                if m["status"] == "not_covered":
                    what, why, fix = (f"No test runs this line, so none can catch `{m['description']}`.", None,
                                      "Add a test that runs this line.")
                else:
                    what, why, fix = mutant_words(m, text, n)
                new = mutated_line(text, m) if text else None
                p = project_of(file)
                rerun = [f'cd "$RUST/{p}" && cargo test{feature_flags(p)}']
                out.append(finding("mutation", "mutant-" + m["status"].replace("_", "-"), "block",
                                   "Mutant survived" if m["status"] == "survived" else "Mutant on an untested line",
                                   what, file, line, why=[why] if why else [], fix=fix,
                                   evidence={"mutant": {k: m.get(k) for k in ("description", "kind", "function",
                                                                              "column", "status", "tests_run")},
                                             "tests": [t["name"] for t in tests[:20]], "tests_count": len(tests),
                                             "caught_by_on_this_line": caught[:5]},
                                   patch=[text, new] if new else None, rerun=rerun,
                                   key_parts=[m.get("function"), m.get("description"), (text or "").strip()]))
    return out


def reach_findings(pr):
    out = []
    regions = collections.defaultdict(list)
    for r in pr.reach:
        if r["state"] == "never-reaches":
            regions[r["finding"]].append(r)
    for key, rs in regions.items():
        first = rs[0]
        t, req = first["test"], first["requirement"]
        test_file = t["path"].split("/")[-1]
        where = next(((r["path"], r["from"]) for r in rs if pr.commentable(r["path"], r["from"])), (None, None))
        names = [run["test"] for run in first["runs"]]
        hits = sorted({line for run in pr.tests["names"] if run["name"] in names
                       for line in lines_of(pr, run["name"], first["path"])})
        lines = f"lines {first['from']}-{first['to']}" if first["to"] > first["from"] else f"line {first['from']}"
        what = f"The test at {test_file}:{t['line']} runs, but never reaches {lines}."
        why = [f"It cites “{pr.spec_text(req['quote'], req['target'])}”"]
        product = PRODUCT_DIRS.get(first["library"], first["library"])
        cls = test_cls(names[0]) if names else None
        rerun = []
        if t.get("repository") == COMMONS and cls:
            rerun = [f'cd "$COMMONS" && TESTSERVER_COVERAGE_DIR=/tmp/pr-findings-cov TESTSERVER_PER_TEST_COVERAGE=1 '
                     f'RUSTUP_TOOLCHAIN=nightly RUSTFLAGS="-C instrument-coverage -Z coverage-options=branch '
                     f'--cfg testserver_coverage" make -C {product}/test-server orchestrate '
                     f'ORCHESTRATE_ARGS="languages=rust tests={cls} workingTreeOverlay.aws-crypto-tools-rust=$RUST"',
                     'python3 "$COMMONS/test-server-common/tools/per_test_coverage.py" build /tmp/pr-findings-cov '
                     '/tmp/pr-findings-cov-out',
                     f'python3 "$COMMONS/test-server-common/tools/per_test_coverage.py" lines '
                     f"/tmp/pr-findings-cov-out/rust.jsonl '{names[0]}'"]
        end = pr.span_end(where[0], where[1], next(r["to"] for r in rs if r["path"] == where[0])) if where[0] else None
        f = finding("reach", "duvet-test-misses-code", "block", "A duvet test never runs this code",
                    what, where[0], where[1], why=why, end_line=end,
                    fix="Make that test reach this code, or move the annotation to the code it does run.",
                    evidence={"requirement": req, "test": t, "regions": [[r["path"], r["from"], r["to"]] for r in rs],
                              "runs": names[:10], "lines_run": ranges(hits), "library": first["library"]},
                    rerun=rerun, key_parts=[req["target"], req["quote"], t["path"], t["line"]])
        out.append(f)
    return out


def lines_of(pr, test, file):
    """The lines of file that one test run hit."""
    names = pr.tests["names"]
    return [line for line, idx in pr.tests["at"].get(file, {}).items() if any(names[i]["name"] == test for i in idx)]


def test_cls(name):
    """The JUnit class of a test server test's name: "a.b.FooTest#[x] does a thing rust-v1" -> "a.b.FooTest"."""
    return name.split("#")[0] if "#" in name else None


def server_findings(pr):
    out = []
    for into, check, kind, title in ((pr.servers, "servers", "test-server-case-failed", "Test server case failed"),
                                     (pr.fuzz, "fuzz", "fuzz-case-failed", "Fuzz case failed")):
        for product, got in into.items():
            groups = collections.OrderedDict()
            for cls, name, msg in got["failed"]:
                base = re.sub(r"\s+\S+-v\d+(?:->\S+-v\d+)?$", "", name)
                groups.setdefault((cls, base), []).append((name, msg))
            for (cls, base), cases in list(groups.items())[:30]:
                seed = re.search(r"\bseed=(-?\d+)", base)
                fuzz = (pr.fuzz_count or "<count>", seed[1]) if check == "fuzz" and seed else None
                out.append(finding(check, kind, "block", title,
                                   f"{product} test server: `{cls.split('.')[-1]}` {base} failed "
                                   f"({plural(len(cases), 'run')}).",
                                   why=[cases[0][1]] if cases[0][1] else [],
                                   fix="Fix the code, or the test if the test is wrong.",
                                   evidence={"class": cls, "cases": [c[0] for c in cases[:10]]},
                                   rerun=server_rerun(PRODUCT_DIRS.get(product, product), cls, fuzz),
                                   key_parts=[product, cls, base]))
    return out


def conformance_findings(pr):
    out = []
    for c in pr.conformance:
        for item in c["open"][:30]:
            out.append(finding("conformance", "conformance-open", "block", "Smithy conformance",
                               f"{c['crate']}: {item.get('message', item.get('id'))}",
                               why=[f"Observed `{item.get('observed')}`, expected `{item.get('expected')}`."
                                    if item.get("observed") else None],
                               fix="Make the code match the Smithy model.",
                               evidence={k: item.get(k) for k in ("id", "check", "subject", "where", "status")},
                               rerun=[f'cd "$RUST" && python3 scripts/smithy-conformance/conform.py --crate {c["crate"]}'],
                               key_parts=[c["crate"], item.get("id")]))
    return out


def api_findings(pr):
    head, base = pr.api.get("head:rust-api.json"), pr.api.get("base:rust-api.json")
    if not head or not base:
        return []
    types, rules = pr.api.get("head:types-rust.json"), pr.api.get("head:expectations.json")
    d, out = api_diff(base, head), []
    rerun = ['cd "$COMMONS/api-examples/types" && python3 rust_api.py --rust-repo "$RUST" '
             '&& python3 compile_rust_types.py --rust-repo "$RUST"']

    def at(span, side="RIGHT"):
        return (span["file"], span["line"]) if span and pr.commentable(span["file"], span["line"], side) else (None, None)

    for a in d["added"]:
        why = [f"`{o['name']}` takes `{o.get('takes')}`. " + " ".join(option_words(types, rules, a, o))
               for o in a.get("options", [])]
        file, line = at(a.get("span"))
        if not file and a.get("options"):
            file, line = at(a["options"][0].get("span"))
        out.append(finding("api", "api-new", "warn", "New API", f"New API: {a['name']}.", file, line, why=why,
                           evidence={"lib": a["lib"], "api": a["id"]}, rerun=rerun, key_parts=[a["lib"], a["id"]]))
    for row in d["options_added"] + d["options_changed"]:
        a, o, was = row["api"], row["option"], row["was"]
        what = (f"`{o['name']}` on the {a['name']} took `{was.get('takes')}`, and now takes `{o.get('takes')}`."
                if was else f"New option `{o['name']}` on the {a['name']}, taking `{o.get('takes')}`.")
        file, line = at(o.get("span"))
        out.append(finding("api", "api-option-changed" if was else "api-option-new", "warn",
                           "API option changed" if was else "New API option", what, file, line,
                           why=option_words(types, rules, a, o), evidence={"lib": a["lib"], "api": a["id"]},
                           rerun=rerun, key_parts=[a["lib"], a["id"], o["name"], o.get("takes")]))
    for row in d["options_removed"]:
        a, o = row["api"], row["option"]
        file, line = at(o.get("span"), "LEFT")
        out.append(finding("api", "api-option-removed", "warn", "API option removed",
                           f"`{o['name']}` is gone from the {a['name']}.", file, line, side="LEFT",
                           evidence={"lib": a["lib"], "api": a["id"]}, key_parts=[a["lib"], a["id"], o["name"]]))
    for a in d["removed"]:
        file, line = at(a.get("span"), "LEFT")
        out.append(finding("api", "api-removed", "warn", "API removed", f"The {a['name']} is gone.", file, line,
                           side="LEFT", evidence={"lib": a["lib"], "api": a["id"]}, key_parts=[a["lib"], a["id"]]))
    return out


# ---------- writing ----------

def build(args):
    gh = GitHub(token())
    repo, n = parse_pr(args.pr)
    pr = PR(gh, repo, n, runs=args.run, excludes=args.exclude, fuzz_count=args.fuzz_count)
    findings = build_findings(pr, args.dashboard)
    order = {"block": 0, "warn": 1}
    findings.sort(key=lambda f: (order[f["level"]], f["file"] is None, f["file"] or "", f["line"] or 0, f["kind"]))
    out = {"schema": 1, "repository": repo, "pr": n, "title": pr.pr["title"], "head": pr.head,
           "base_ref": pr.base_ref, "ci_commit": pr.ci_commit, "runs": [r["id"] for r in pr.runs],
           "dashboard": pr.dashboard(args.dashboard), "read": dict(pr.read), "missing": pr.missing,
           "checked": {check: sorted(folders) for check, folders in pr.checked.items()},
           "errors": pr.errors, "findings": findings}
    text = json.dumps(out, indent=1) + "\n"
    if args.out:
        Path(args.out).write_text(text)
    summary = summary_markdown(out)
    if args.summary:
        with open(args.summary, "a") as f:
            f.write(summary)
    if not args.out:
        print(text)
    print(summary_text(out), file=sys.stderr)
    return out


def summary_text(data):
    found = data["findings"]
    blocks = sum(f["level"] == "block" for f in found)
    lines = [f"{data['repository']}#{data['pr']}: {plural(len(found), 'finding')} ({blocks} blocking)"]
    for f in found:
        where = f"{f['file']}:{f['line']}" if f["file"] else "(no line)"
        lines.append(f"  {f['level']:5} {f['kind']:26} {where}  {f['what']}")
    if data["missing"]:
        lines.append("  missing: " + ", ".join(data["missing"]))
    for e in data.get("errors", []):
        lines.append(f"  could not read {e}")
    return "\n".join(lines)


def summary_markdown(data):
    found = data["findings"]
    out = [f"### What CI found on this PR", ""]
    if not found:
        out.append("Nothing to look at." + (f" No results yet for: {', '.join(data['missing'])}." if data["missing"] else ""))
        return "\n".join(out) + "\n"
    out += ["| | Where | Finding |", "| --- | --- | --- |"]
    for f in found:
        where = f"`{f['file']}:{f['line']}`" if f["file"] else ""
        out.append(f"| {'blocks' if f['level'] == 'block' else 'note'} | {where} | "
                   f"{f['what'].replace('|', '/')} [Dashboard]({f['links']['dashboard']}) |")
    if data["missing"]:
        out += ["", f"No results yet for: {', '.join(data['missing'])}."]
    if data.get("errors"):
        out += ["", "Could not read: " + "; ".join(data["errors"])]
    out += ["", f"[All of it on the dashboard]({data['dashboard']})", ""]
    return "\n".join(out)


def comment_body(f):
    """The review comment for one finding. A 👎 on it counts as not useful, which the dashboard shows."""
    label = "blocks merging" if f["level"] == "block" else "note"
    out = [f"**{f['title']}** ({label})"]
    if f["what"].rstrip(".") != f["title"]:
        out += ["", f["what"]]
    if f["why"]:
        out += [""] + f["why"]
    if f.get("suggestion") is not None:
        out += ["", "```suggestion", f["suggestion"], "```"]
    ci = f["links"].get("ci_name") or "CI run"
    out += ["", f"[View in dashboard]({f['links']['dashboard']}) · [{ci}]({f['links']['ci']})"]
    out.append(MARKER + json.dumps({"key": f["key"], "kind": f["kind"], "check": f["check"]}) + " -->")
    return "\n".join(out)


# ---------- posting ----------

def marker_of(body):
    got = re.search(re.escape(MARKER) + r"(\{.*?\}) -->", body or "")
    return json.loads(got[1]) if got else None


FIXED = re.compile(r"\n\n✓ Fixed in `[0-9a-f]{7}`\.$")


def read_here(data, check, file):
    """Whether this run read the results that a finding of check on file comes from."""
    folders = data.get("checked", {}).get(check, [])
    return "" in folders or folder_of(file or "") in folders


SUMMARY = re.compile(r"^CI found (\d+ things?|nothing) to look at")


def summary_body(data, off=()):
    """The body of a review that posts findings comments. Each run sets every such review's body to it."""
    shown = [f for f in data["findings"] if f["file"] and f["kind"] not in off]
    link = f"[View in dashboard]({data['dashboard']})"
    if not shown:
        return f"CI found nothing to look at on `{data['head'][:7]}`. {link}"
    blocks = sum(f["level"] == "block" for f in shown)
    return f"CI found {plural(len(shown), 'thing')} to look at on `{data['head'][:7]}` ({blocks} blocking). {link}"


def plan(data, comments, threads, off=(), login="github-actions[bot]", reviews=()):
    """What to do so the PR's comments match the findings.

    comments: the PR's review comments; threads: {first comment id: {"id", "resolved", "comment", "hidden"}},
    where comment is the first comment's node id and hidden says that comment is hidden; login: the account
    that posts, whose comments with a marker are the ones to keep up to date; reviews: the PR's reviews.
    Returns {"create": [finding], "update": [(comment id, body)], "close": [thread], "reopen": [thread],
    "hide": [thread], "summary": <the body of a new review>, "summaries": [(review id, body)]}.
    """
    wanted = {f["key"]: f for f in data["findings"] if f["file"] and f["kind"] not in off}
    ours = [c for c in comments if not c.get("in_reply_to_id") and marker_of(c.get("body"))
            and (c.get("user") or {}).get("login") == login]
    summary = summary_body(data, off)
    # A review's body is the summary of the run that posted it; its counts and link go stale.
    summaries = [(r["id"], summary) for r in reviews if (r.get("user") or {}).get("login") == login
                 and SUMMARY.match(r.get("body") or "") and r["body"] != summary]
    actions = {"create": [], "update": [], "close": [], "reopen": [], "hide": [], "summary": summary,
               "summaries": summaries}
    seen = set()
    for c in sorted(ours, key=lambda c: c["id"], reverse=True):
        marker, thread = marker_of(c["body"]), threads.get(c["id"])
        if marker.get("kind") in off or marker.get("check", "lines") not in CHECKS:
            # A kind turned off, or a check this script no longer has: its comment goes, but nothing was fixed.
            if thread and not thread["hidden"]:
                actions["hide"].append(thread)
            continue
        f = wanted.get(marker["key"])
        # GitHub gives a comment on several lines its first line as start_line, and its last as line.
        same_place = (f and (c.get("start_line") or c.get("line")) == f["line"]
                      and c.get("line") == (f.get("end_line") or f["line"])
                      and c.get("path") == f["file"] and (c.get("side") or "RIGHT") == f["side"])
        if f and marker["key"] not in seen and same_place:
            seen.add(marker["key"])
            body = comment_body(f)
            if c["body"] != body:
                actions["update"].append((c["id"], body))
            if thread and (thread["resolved"] or thread["hidden"]):
                actions["reopen"].append(thread)
            continue
        if not thread or thread["resolved"] or thread["hidden"]:
            continue
        if not f:
            # A finding is also missing when the run did not read its check's results, and that is no fix.
            if not read_here(data, marker.get("check"), c.get("path")):
                continue
            if not FIXED.search(c["body"]):
                actions["update"].append((c["id"], c["body"] + f"\n\n✓ Fixed in `{data['head'][:7]}`."))
        # The finding is gone, moved, or has a newer comment.
        actions["close"].append(thread)
    actions["create"] = [f for key, f in wanted.items() if key not in seen]
    return actions


THREADS = """query($owner: String!, $name: String!, $n: Int!, $after: String) {
  repository(owner: $owner, name: $name) { pullRequest(number: $n) {
    reviewThreads(first: 100, after: $after) { pageInfo { hasNextPage endCursor }
      nodes { id isResolved comments(first: 1) { nodes { databaseId id isMinimized } } } } } } }"""


def threads_of(gh, repo, n):
    owner, name = repo.split("/")
    out, after = {}, None
    while True:
        got = gh.graphql(THREADS, owner=owner, name=name, n=n, after=after)["repository"]["pullRequest"]["reviewThreads"]
        for t in got["nodes"]:
            for first in t["comments"]["nodes"]:
                out[first["databaseId"]] = {"id": t["id"], "resolved": t["isResolved"], "comment": first["id"],
                                            "hidden": first["isMinimized"]}
        if not got["pageInfo"]["hasNextPage"]:
            return out
        after = got["pageInfo"]["endCursor"]


# The changes to a findings comment's thread, by GraphQL mutation.
MUTATIONS = {
    "resolveReviewThread": "mutation($id: ID!) { resolveReviewThread(input: {threadId: $id}) { thread { id } } }",
    "unresolveReviewThread": "mutation($id: ID!) { unresolveReviewThread(input: {threadId: $id}) { thread { id } } }",
    "minimizeComment": ("mutation($id: ID!, $why: ReportedContentClassifiers!) { minimizeComment("
                        "input: {subjectId: $id, classifier: $why}) { minimizedComment { isMinimized } } }"),
    "unminimizeComment": "mutation($id: ID!) { unminimizeComment(input: {subjectId: $id}) { unminimizedComment { isMinimized } } }",
}


def refused(e):
    """Whether GitHub refused the token, as it refuses the read-only token of a pull request from a fork."""
    return " 403 " in str(e) or "Resource not accessible" in str(e)


def post(args):
    data = json.loads(Path(args.findings).read_text())
    gh = GitHub(token())
    repo, n = data["repository"], data["pr"]
    comments = gh.pages(f"repos/{repo}/pulls/{n}/comments")
    threads = threads_of(gh, repo, n)
    reviews = gh.pages(f"repos/{repo}/pulls/{n}/reviews")
    actions = plan(data, comments, threads, off=set(args.off), login=args.login, reviews=reviews)
    print(f"create {len(actions['create'])}, edit {len(actions['update'])}, close {len(actions['close'])}, "
          f"reopen {len(actions['reopen'])}, hide {len(actions['hide'])}, summaries {len(actions['summaries'])}")
    if args.dry_run:
        for f in actions["create"]:
            print(f"--- would comment on {f['file']}:{f['line']} ({f['side']})\n{comment_body(f)}\n")
        return
    apply(gh, data, actions)


def apply(gh, data, actions):
    """Makes the changes that plan returned."""
    repo, n = data["repository"], data["pr"]
    try:
        if actions["create"]:
            review = {"commit_id": data["head"], "event": "COMMENT", "body": actions["summary"],
                      "comments": [{"path": f["file"], "side": f["side"], "body": comment_body(f),
                                    **({"start_line": f["line"], "start_side": f["side"], "line": f["end_line"]}
                                       if f.get("end_line") else {"line": f["line"]})} for f in actions["create"]]}
            try:
                gh.request("POST", f"repos/{repo}/pulls/{n}/reviews", review)
            except RuntimeError as e:
                if refused(e):
                    raise
                # One bad line fails the whole review, so each comment is tried alone.
                print(f"the review failed ({e}); posting each comment alone")
                for c in review["comments"]:
                    try:
                        gh.request("POST", f"repos/{repo}/pulls/{n}/comments", {**c, "commit_id": data["head"]})
                    except RuntimeError as one:
                        print(f"could not comment on {c['path']}:{c['line']}: {one}")
        for cid, body in actions["update"]:
            gh.request("PATCH", f"repos/{repo}/pulls/comments/{cid}", {"body": body})
        for rid, body in actions["summaries"]:
            gh.request("PUT", f"repos/{repo}/pulls/{n}/reviews/{rid}", {"body": body})
    except RuntimeError as e:
        # A pull request from a fork gets a read-only token, so its comments stay in the findings artifact.
        if refused(e):
            print(f"::notice::This run cannot comment on the PR ({e}). The findings are in the pr-findings artifact.")
            return
        raise
    refusals = set()

    def run(name, node, **more):
        """Runs one mutation, and returns False when GitHub refuses it to this token."""
        if name in refusals:
            return False
        try:
            gh.graphql(MUTATIONS[name], id=node, **more)
            return True
        except RuntimeError as e:
            if not refused(e):
                raise
            print(f"GitHub refused {name} to this token: {e}")
            refusals.add(name)
            return False

    for t in actions["close"]:
        # GitHub resolves a thread only for a token with contents: write, which the PR findings job does
        # not get. Hiding the comment as resolved folds it away the same way.
        if not run("resolveReviewThread", t["id"]):
            run("minimizeComment", t["comment"], why="RESOLVED")
    for t in actions["hide"]:
        run("minimizeComment", t["comment"], why="OUTDATED")
    for t in actions["reopen"]:
        if t["hidden"]:
            run("unminimizeComment", t["comment"])
        if t["resolved"]:
            run("unresolveReviewThread", t["id"])


def line(args):
    gh = GitHub(token())
    repo, n = parse_pr(args.pr)
    file, number = args.where.rsplit(":", 1)
    number = int(number)
    pr = PR(gh, repo, n, runs=args.run)
    pr.wanted.add(file)
    if file not in pr.rows:
        # A file the PR does not change: read its coverage and tests too.
        pr._read_coverage()
        pr._read_servers()
    record = {
        "file": file, "line": number, "code": pr.line_text(file, number), "changed": number in pr.changed(file),
        "local_hits": pr.local.get(file, {}).get(number), "server_hits": pr.server.get(file, {}).get(number),
        "branches": pr.branches.get(file, {}).get(number, {}),
        "mutants": [{k: m.get(k) for k in ("status", "description", "killed_by", "function")}
                    for m in pr.mutants.get(file, {}).get(number, [])],
        "tests": [t["name"] for t in pr.tests_at(file, number)],
        "duvet": [b for b in pr.blocks.get(file, []) if b["start"] <= number <= b["end"] or b["code"] == number],
        "reach": [r for r in pr.reach if r["path"] == file and r["from"] <= number <= r["to"]],
    }
    print(json.dumps(record, indent=1, default=str))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    b = commands.add_parser("build")
    b.add_argument("pr")
    b.add_argument("--run", action="append", default=[], help="a workflow run id to read; repeat for more")
    b.add_argument("--exclude", action="append", default=[], help="a glob of files the line checks leave out")
    b.add_argument("--fuzz-count", help="TESTSERVER_FUZZ of the fuzz runs, for their rerun commands")
    b.add_argument("--dashboard", default=DASHBOARD)
    b.add_argument("--out")
    b.add_argument("--summary")
    p = commands.add_parser("post")
    p.add_argument("findings")
    p.add_argument("--off", action="append", default=[], help="a finding kind not to comment on")
    p.add_argument("--login", default="github-actions[bot]", help="the account the token posts as")
    p.add_argument("--dry-run", action="store_true")
    ln = commands.add_parser("line")
    ln.add_argument("pr")
    ln.add_argument("where")
    ln.add_argument("--run", action="append", default=[])
    args = parser.parse_args()
    {"build": build, "post": post, "line": line}[args.command](args)


if __name__ == "__main__":
    main()
