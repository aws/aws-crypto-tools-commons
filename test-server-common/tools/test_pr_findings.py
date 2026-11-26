"""Run with: python3 -m unittest discover -s test-server-common/tools"""

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

import pr_findings as pf


def zipped(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    return buf.getvalue()


# One pull request with one new library file, a test file and a test server config change.
HEAD, BASE = "a" * 40, "b" * 40
REPO, PR = "aws/aws-crypto-tools-rust", "repos/aws/aws-crypto-tools-rust/pulls/7"
SOURCE = """pub struct KBuilder {}
impl KBuilder {
    pub fn key_id(self, id: &str) -> Result<Self, Error> {
        if id.len() >= LIMIT {
            return Err(Error::TooLong);
        }
        //= spec/k.md#init
        //# It MUST check.
        check(self)
    }
}"""
TESTS = "#[test]\n#[ignore]\nfn checks() {}"
FEATURES_BASE = '{"supportedFeatures": ["a"], "unsupportedFeatures": []}'
FEATURES_HEAD = '{\n  "supportedFeatures": ["a"],\n  "unsupportedFeatures": [\n    "b"\n  ]\n}'


def added(text):
    lines = text.split("\n")
    return f"@@ -0,0 +1,{len(lines)} @@\n" + "\n".join("+" + line for line in lines)


def artifact(id, name, run=50):
    return {"id": id, "name": name, "expired": False, "created_at": f"2026-11-26T00:00:{id:02d}Z", "run_id": run}


MUTANTS = {"summary": {"library": "mpl", "commit": HEAD}, "mutants": [
    {"file": "mpl/src/k.rs", "line": 4, "column": 21, "kind": "binary", "description": "replace >= with >",
     "function": "key_id", "status": "survived", "tests_run": 3},
    {"file": "mpl/src/k.rs", "line": 9, "column": 9, "kind": "fn_value", "description": "replace the body of check with ()",
     "function": "key_id", "status": "killed", "killed_by": "aws-crypto-mpl::t::checks"}]}
LCOV = ("SF:mpl/src/k.rs\nDA:3,3\nDA:4,3\nDA:5,0\nDA:9,3\nBRDA:4,0,0,0\nBRDA:4,0,1,3\nend_of_record\n"
        "SF:mpl/test-server/src/handlers.rs\nDA:1,0\nend_of_record\n")
PER_TEST = json.dumps({"test": "aws-crypto-mpl::t::checks", "source": "local", "repository": REPO, "status": "passed",
                       "files": {"mpl/src/k.rs": [3, 4, 9]}}) + "\n"
REACH = {"library": "mpl", "language": "rust", "commit": HEAD, "findings": [
    {"state": "never-reaches", "requirement": {"target": "spec/k.md#init", "quote": "It MUST check."},
     "test_annotation": {"repository": pf.COMMONS, "path": "mpl/test-server/tests/KTest.java", "line": 30},
     "runs": [{"test": "a.b.KTest#[k] it checks rust-v1", "status": "passed"}],
     "implementations": [{"path": "mpl/src/k.rs", "line": 7, "region": [9, 9]}]},
    {"state": "ok", "requirement": {"target": "spec/k.md#ids", "quote": "It MUST take an ID."},
     "test_annotation": {"repository": pf.COMMONS, "path": "mpl/test-server/tests/KTest.java", "line": 20},
     "runs": [], "implementations": [{"path": "mpl/src/k.rs", "line": 2, "region": [3, 3]}]}]}
JUNIT = ('<testsuite><testcase classname="a.b.KTest" name="[k] it builds rust-v1"/>'
         '<testcase classname="a.b.KTest" name="[k] it fails rust-v1"><failure message="boom &amp; more"/></testcase>'
         '</testsuite>')
FUZZ = ('<testsuite><testcase classname="a.b.KTest" name="fuzz 3 seed=42: weird input rust-v1">'
        '<failure message="bad"/></testcase></testsuite>')
API_HEAD = {"apis": [{"lib": "mpl", "id": "k-keyring", "name": "K keyring", "span": {"file": "mpl/src/k.rs", "line": 1, "end": 1},
                      "options": [{"name": "key_id", "takes": "&str", "span": {"file": "mpl/src/k.rs", "line": 3, "end": 10}}]}]}
TYPES = {"apis": [{"lib": "mpl", "id": "k-keyring", "options": [{"key": "mpl|k-keyring|keyId", "name": "key_id"}]}],
         "rows": {"mpl|k-keyring|keyId": [{"type": "&str", "calls": 0, "code": ".key_id(x)", "kind": "text"},
                                          {"type": "PathBuf", "calls": 2, "code": ".key_id(&read(x))", "kind": "path"}]}}


def github(over=None):
    """The replies of a stand-in GitHub, by API path."""
    arts = [artifact(1, "mutation-results-mpl"), artifact(2, "local-coverage-mpl"), artifact(3, "per-test-coverage-mpl"),
            artifact(4, "duvet-test-reach-mpl-rust"), artifact(5, "mpl-test-server-reports"),
            artifact(6, "mpl-test-server-fuzz-reports"), artifact(7, "smithy-conformance-mpl"),
            artifact(8, "api-types-rust"), artifact(9, "api-types-rust-base")]
    replies = {
        PR: {"title": "feat(mpl): add K", "html_url": "https://github.com/aws/aws-crypto-tools-rust/pull/7",
             "head": {"sha": HEAD}, "base": {"sha": BASE, "ref": "main"}},
        f"{PR}/files": [{"filename": "mpl/src/k.rs", "status": "added", "patch": added(SOURCE)},
                        {"filename": "mpl/tests/t.rs", "status": "added", "patch": added(TESTS)},
                        {"filename": "mpl/test-server/src/handlers.rs", "status": "added", "patch": added("fn h() {}")},
                        {"filename": "mpl/test-server/feature-config.json", "status": "modified",
                         "patch": "@@ -1 +1,6 @@\n-" + FEATURES_BASE + "\n" + "\n".join("+" + l for l in FEATURES_HEAD.split("\n"))}],
        f"repos/{REPO}/commits/{HEAD}/check-runs": {"check_runs": [
            {"id": 1, "name": "Mutation testing (mpl)", "status": "completed", "conclusion": "failure", "html_url": "https://ci/1"},
            {"id": 2, "name": "pr-ci-all-required", "status": "completed", "conclusion": "failure", "html_url": "https://ci/2"},
            {"id": 3, "name": "Rust tests", "status": "completed", "conclusion": "success", "html_url": "https://ci/3"}]},
        f"repos/{REPO}/actions/runs?head_sha={HEAD}": {"workflow_runs": [{"id": 50, "html_url": "https://ci/run/50"}]},
        f"repos/{REPO}/actions/runs/50/artifacts": {"artifacts": arts},
        f"repos/{REPO}/compare/{BASE}...{HEAD}": {"merge_base_commit": {"sha": BASE}},
        f"raw:mpl/src/k.rs@{HEAD}": SOURCE, f"raw:mpl/tests/t.rs@{HEAD}": TESTS,
        f"raw:mpl/test-server/src/handlers.rs@{HEAD}": "fn h() {}",
        f"raw:mpl/test-server/feature-config.json@{HEAD}": FEATURES_HEAD,
        f"raw:mpl/test-server/feature-config.json@{BASE}": FEATURES_BASE,
        "zip:1": zipped({"results.json": json.dumps(MUTANTS)}),
        "zip:2": zipped({"mpl.lcov": LCOV}),
        "zip:3": zipped({"per-test-coverage/rust.jsonl": PER_TEST}),
        "zip:4": zipped({"mpl-rust.json": json.dumps(REACH)}),
        "zip:5": zipped({"mpl/test-server/tests/build/test-results/test/TEST-a.b.KTest.xml": JUNIT}),
        # The fuzz run also writes coverage, of the line no test runs.
        "zip:6": zipped({"mpl/test-server/tests/build/test-results/test/TEST-a.b.KTest.xml": FUZZ,
                         "mpl/test-server/build/coverage/rust.json": json.dumps({"repository": REPO, "commit": HEAD}),
                         "mpl/test-server/build/coverage/rust.lcov": "SF:mpl/src/k.rs\nDA:5,9\nend_of_record\n"}),
        "zip:7": zipped({"report.md": "- result: **FAIL**\n", "findings.json": json.dumps(
            [{"id": "m1", "status": "open", "message": "`x` is missing", "observed": "a", "expected": "b"},
             {"id": "m2", "status": "accepted", "message": "fine"}])}),
        "zip:8": zipped({"api-examples/types/rust-api.json": json.dumps(API_HEAD),
                         "dashboard/api-examples/types-rust.json": json.dumps(TYPES)}),
        "zip:9": zipped({"api-examples/types/rust-api.json": json.dumps({"apis": []})}),
    }
    replies.update(over or {})
    return replies


class FakeGitHub:
    def __init__(self, replies):
        self.replies, self.sent = replies, []

    def get(self, path, raw=False, accept=None):
        if path.endswith("/zip"):
            got = self.replies[f"zip:{int(path.split('/')[-2])}"]
            if isinstance(got, Exception):
                raise got
            return got
        if path not in self.replies:
            raise RuntimeError(f"GitHub 404 for GET {path}")
        return self.replies[path]

    def pages(self, path, key=None, limit=30):
        got = self.get(path)
        return got[key] if key else got

    def raw_file(self, repo, path, ref):
        if f"raw:{path}@{ref}" not in self.replies:
            raise RuntimeError(f"GitHub 404 for {path}")
        return self.replies[f"raw:{path}@{ref}"]


def build(replies=None, **kw):
    with tempfile.TemporaryDirectory() as tmp:
        pf.CACHE = Path(tmp)
        pr = pf.PR(FakeGitHub(replies or github()), REPO, 7, excludes=["*/test-server/*"], fuzz_count="20", **kw)
        return pr, pf.build_findings(pr)


def by_kind(findings):
    out = {}
    for f in findings:
        out.setdefault(f["kind"], []).append(f)
    return out


class Findings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pr, cls.findings = build()
        cls.kinds = by_kind(cls.findings)

    def test_a_changed_line_no_test_runs_is_a_blocking_finding_on_that_line(self):
        (f,) = self.kinds["line-not-run"]
        self.assertEqual((f["file"], f["line"], f["level"]), ("mpl/src/k.rs", 5, "block"))
        self.assertEqual(f["why"], ["1 test run line 4, just above, but none runs this one."])

    def test_a_branch_no_test_takes_names_the_condition_and_its_side(self):
        (f,) = self.kinds["branch-not-taken"]
        self.assertEqual(f["line"], 4)
        self.assertEqual(f["why"], ["No test makes `id.len() >= LIMIT` true."])

    def test_a_surviving_mutant_says_what_changed_why_no_test_saw_it_and_how_to_try_it(self):
        (f,) = self.kinds["mutant-survived"]
        self.assertEqual(f["what"], "`>=` became `>` here, and all 3 tests that run this line still passed.")
        self.assertEqual(f["why"], ["The two differ only when `id.len()` equals `LIMIT`, and no test has that."])
        self.assertEqual(f["patch"], ["        if id.len() >= LIMIT {", "        if id.len() > LIMIT {"])
        self.assertEqual(f["rerun"], ['cd "$RUST/mpl" && cargo test --all-features'])

    def test_a_killed_mutant_is_not_a_finding(self):
        self.assertEqual([f["line"] for f in self.findings if f["check"] == "mutation"], [4])

    def test_a_duvet_test_that_misses_its_code_says_where_the_test_went(self):
        (f,) = self.kinds["duvet-test-misses-code"]
        self.assertEqual((f["file"], f["line"]), ("mpl/src/k.rs", 9))
        self.assertIn("It runs, but never reaches lines 9-9.", f["why"])
        self.assertIn("make -C mpl/test-server orchestrate", f["rerun"][0])

    def test_failed_test_server_and_fuzz_cases_are_findings_on_no_line_with_a_rerun(self):
        (server,) = self.kinds["test-server-case-failed"]
        self.assertEqual((server["file"], server["why"]), (None, ["boom & more"]))
        self.assertIn("tests=a.b.KTest ", server["rerun"][0])
        (fuzz,) = self.kinds["fuzz-case-failed"]
        self.assertIn("TESTSERVER_FUZZ=20 TESTSERVER_FUZZ_SEED=42 make", fuzz["rerun"][0])

    def test_fuzz_runs_do_not_count_toward_line_coverage(self):
        self.assertEqual(self.pr.read["fuzz"], ["mpl (1 case)"])
        self.assertNotIn("mpl/src/k.rs", self.pr.server)

    def test_an_open_conformance_finding_counts_and_an_accepted_one_does_not(self):
        self.assertEqual([f["evidence"]["id"] for f in self.kinds["conformance-open"]], ["m1"])

    def test_a_failed_check_is_a_finding_but_the_check_that_sums_up_the_others_is_not(self):
        self.assertEqual([f["what"] for f in self.kinds["check-failed"]], ["`Mutation testing (mpl)` failed."])

    def test_a_new_api_is_a_note_on_its_type_with_how_callers_pass_each_option(self):
        (f,) = self.kinds["api-new"]
        self.assertEqual((f["level"], f["line"]), ("warn", 1))
        self.assertIn("Of 2 types a caller may hold, 1 pass as is, 0 need one call, 1 need more", f["why"][0])
        self.assertIn("`PathBuf`: `.key_id(&read(x))`", f["why"][0])

    def test_changes_that_weaken_the_checks_are_notes(self):
        self.assertEqual([(f["file"], f["line"]) for f in self.kinds["cheat-ignore"]], [("mpl/tests/t.rs", 2)])
        (feature,) = self.kinds["cheat-unsupported-feature"]
        self.assertEqual((feature["line"], feature["level"]), (4, "warn"))

    def test_the_excluded_test_server_code_gets_no_line_findings(self):
        self.assertEqual([f["file"] for f in self.kinds["line-not-run"]], ["mpl/src/k.rs"])

    def test_nothing_is_missing_when_every_check_uploaded_results(self):
        self.assertEqual(self.pr.missing, [])


class Narrowed(unittest.TestCase):
    def test_an_exclude_on_a_check_is_a_note_but_one_on_another_tool_is_not(self):
        workflow = "      run: diff-cover lcov.info --exclude '*/a/*'\n        --exclude '*/test-server/*' --fuzz-count 20"
        replies = github({f"{PR}/files": [{"filename": ".github/workflows/ci.yml", "status": "modified", "patch": added(workflow)}]})
        _, findings = build(replies)
        self.assertEqual([(f["kind"], f["line"]) for f in findings if f["check"] == "cheat"], [("cheat-check-narrowed", 1)])


class Missing(unittest.TestCase):
    def test_a_code_change_with_no_mutation_results_or_api_types_says_so(self):
        replies = github()
        replies[f"repos/{REPO}/actions/runs/50/artifacts"] = {"artifacts": [artifact(2, "local-coverage-mpl")]}
        pr, _ = build(replies)
        self.assertEqual(pr.missing, ["mutation results", "API types"])


class Attempts(unittest.TestCase):
    def test_an_artifact_from_an_earlier_attempt_of_the_run_is_left_out_when_the_newest_attempt_uploaded_one(self):
        replies = github()
        replies[f"repos/{REPO}/actions/runs?head_sha={HEAD}"]["workflow_runs"][0]["run_started_at"] = "2026-11-26T00:00:06Z"
        replies[f"repos/{REPO}/actions/runs/50/artifacts"]["artifacts"].append(artifact(13, "mpl-test-server-reports"))
        replies["zip:13"] = zipped({"mpl/test-server/tests/build/test-results/test/TEST-a.b.KTest.xml":
                                    '<testsuite><testcase classname="a.b.KTest" name="[k] it fails rust-v1"/></testsuite>'})
        _, findings = build(replies)
        self.assertNotIn("test-server-case-failed", by_kind(findings))

    def test_an_artifact_github_cannot_serve_is_an_error_and_the_rest_still_count(self):
        replies = github({"zip:5": RuntimeError("GitHub 500 for GET .../zip: Failed to generate URL to download artifact")})
        pr, findings = build(replies)
        self.assertEqual(len(pr.errors), 1)
        self.assertIn("mpl-test-server-reports: GitHub 500", pr.errors[0])
        self.assertIn("mutant-survived", by_kind(findings))


class NewestReport(unittest.TestCase):
    def test_only_the_newest_copy_of_a_whole_report_counts(self):
        replies = github()
        replies[f"repos/{REPO}/actions/runs/50/artifacts"]["artifacts"].append(artifact(11, "mutation-results-mpl"))
        replies["zip:11"] = zipped({"results.json": json.dumps({"summary": {"library": "mpl"}, "mutants": []})})
        pr, findings = build(replies)
        self.assertNotIn("mutant-survived", by_kind(findings))


class Keys(unittest.TestCase):
    def test_two_findings_with_the_same_text_in_one_file_get_different_keys(self):
        source = "//= spec/a.md#x\n//= type=implication\n//# A MUST.\nlet a = 1;\n//= spec/a.md#y\n//= type=implication\n//# B MUST.\nlet b = 2;"
        replies = github({f"{PR}/files": [{"filename": "mpl/src/a.rs", "status": "added", "patch": added(source)}],
                          f"raw:mpl/src/a.rs@{HEAD}": source})
        _, findings = build(replies)
        keys = [f["key"] for f in findings if f["kind"] == "cheat-duvet-implication"]
        self.assertEqual(len(set(keys)), 2)


class Words(unittest.TestCase):
    def test_operands_stop_at_the_logic_operator_and_the_block(self):
        line = "    if kms_key_id.is_empty() || kms_key_id.len() > MAX_LENGTH {"
        self.assertEqual(pf.operands(line, line.index(">") + 1, ">"), ("kms_key_id.len()", "MAX_LENGTH"))

    def test_each_mutant_kind_has_its_own_reason(self):
        line = "    if a == b {"
        self.assertEqual(pf.mutant_words({"kind": "binary", "description": "replace == with !=", "column": 10}, line, 2)[1],
                         "No test depends on the result of this comparison.")
        self.assertEqual(pf.mutant_words({"kind": "condition", "description": "replace the condition with true"}, line, 2)[1],
                         "No test checks what happens when this condition is false.")
        self.assertEqual(pf.mutant_words({"kind": "fn_value", "description": "replace the body of f with Ok(())"}, line, 2)[1],
                         "No test checks what `f` returns.")

    def test_conditions_inside_a_group_are_split_and_unwrapped(self):
        self.assertEqual(pf.leaf_conditions('if a.is_empty() || (b != "key" && c(d)) {'),
                         ["a.is_empty()", 'b != "key"', "c(d)"])

    def test_the_second_count_of_a_condition_is_its_false_side(self):
        self.assertEqual(pf.branch_words("if x > 1 {", {"0,0": 4, "0,1": 0}), ["No test makes `x > 1` false."])


class Api(unittest.TestCase):
    def test_options_added_changed_and_removed_on_an_existing_api(self):
        base = {"apis": [{"lib": "mpl", "id": "k", "name": "K", "options": [{"name": "a", "takes": "String"},
                                                                          {"name": "gone", "takes": "u8"}]}]}
        head = {"apis": [{"lib": "mpl", "id": "k", "name": "K", "options": [{"name": "a", "takes": "&str"},
                                                                          {"name": "new", "takes": "u8"}]}]}
        d = pf.api_diff(base, head)
        self.assertEqual([r["option"]["name"] for r in d["options_added"]], ["new"])
        self.assertEqual([r["option"]["name"] for r in d["options_changed"]], ["a"])
        self.assertEqual([r["option"]["name"] for r in d["options_removed"]], ["gone"])
        self.assertEqual(d["added"] + d["removed"], [])

    def test_a_rule_the_option_breaks_is_named(self):
        rules = {"rules": {"mpl|k-keyring|keyId": {"refuse": ["text"], "why": "Text is not a key."}}}
        words = pf.option_words(TYPES, rules, {"lib": "mpl", "id": "k-keyring"}, {"name": "key_id"})
        self.assertEqual(words[-1], "It takes text as is, but the rule says: Text is not a key.")


def comment(key, line=5, path="mpl/src/k.rs", login="github-actions[bot]", cid=1, body=None, side="RIGHT"):
    return {"id": cid, "line": line, "path": path, "side": side, "user": {"login": login},
            "body": body or ("old text\n" + pf.MARKER + json.dumps({"key": key}) + " -->")}


class Plan(unittest.TestCase):
    def setUp(self):
        _, findings = build()
        self.data = {"repository": REPO, "pr": 7, "head": HEAD, "findings": findings}
        self.line = next(f for f in findings if f["kind"] == "line-not-run")

    def test_a_new_finding_gets_a_comment(self):
        plan = pf.plan(self.data, [], {})
        self.assertIn(self.line["key"], [f["key"] for f in plan["create"]])
        self.assertFalse(any(f["file"] is None for f in plan["create"]))

    def test_a_finding_with_a_comment_on_its_line_gets_that_comment_edited_not_a_new_one(self):
        plan = pf.plan(self.data, [comment(self.line["key"])], {1: {"id": "T1", "resolved": False}})
        self.assertNotIn(self.line["key"], [f["key"] for f in plan["create"]])
        self.assertEqual(plan["update"], [(1, pf.comment_body(self.data, self.line))])

    def test_a_comment_whose_finding_is_gone_is_marked_fixed_and_its_thread_resolved(self):
        plan = pf.plan(self.data, [comment("gone")], {1: {"id": "T1", "resolved": False}})
        self.assertEqual(plan["resolve"], ["T1"])
        self.assertTrue(plan["update"][0][1].endswith("\n\n✓ Fixed in `aaaaaaa`."))

    def test_a_finding_that_comes_back_reopens_its_thread(self):
        plan = pf.plan(self.data, [comment(self.line["key"])], {1: {"id": "T1", "resolved": True}})
        self.assertEqual(plan["unresolve"], ["T1"])

    def test_a_finding_that_moved_lines_gets_a_new_comment_and_the_old_thread_is_resolved(self):
        plan = pf.plan(self.data, [comment(self.line["key"], line=3)], {1: {"id": "T1", "resolved": False}})
        self.assertIn(self.line["key"], [f["key"] for f in plan["create"]])
        self.assertEqual(plan["resolve"], ["T1"])

    def test_other_accounts_comments_and_kinds_turned_off_are_left_alone(self):
        plan = pf.plan(self.data, [comment("gone", login="someone")], {1: {"id": "T1", "resolved": False}},
                       off={"line-not-run"})
        self.assertEqual(plan["resolve"], [])
        self.assertNotIn(self.line["key"], [f["key"] for f in plan["create"]])


class Body(unittest.TestCase):
    def test_the_comment_links_the_dashboard_at_its_line_and_carries_its_key(self):
        pr, findings = build()
        f = next(f for f in findings if f["kind"] == "mutant-survived")
        body = pf.comment_body({"repository": REPO, "pr": 7}, f)
        self.assertIn("[View in dashboard](https://aws.github.io/aws-crypto-tools-commons/"
                      "?pr=aws/aws-crypto-tools-rust%237&line=mpl/src/k.rs:4#pr-review)", body)
        self.assertIn("```diff\n-        if id.len() >= LIMIT {\n+        if id.len() > LIMIT {\n```", body)
        self.assertEqual(pf.marker_of(body)["key"], f["key"])


if __name__ == "__main__":
    unittest.main()
