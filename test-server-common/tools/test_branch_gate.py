"""Run with: python3 -m unittest discover -s test-server-common/tools"""

import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path

import branch_gate as gate


class ReadBranchesTest(unittest.TestCase):

    def test_a_line_that_never_ran_counts_as_untaken(self):
        lcov = "SF:src/a.rs\nDA:3,0\nBRDA:3,0,0,-\nBRDA:3,0,1,-\nend_of_record\n"
        self.assertEqual({("src/a.rs", 3): {("0", "0"): 0, ("0", "1"): 0}},
                         gate.read_branches(lcov, "/repo"))

    def test_an_absolute_path_is_made_relative_to_the_root(self):
        lcov = "SF:/repo/src/a.rs\nBRDA:3,0,0,2\nend_of_record\n"
        self.assertEqual({("src/a.rs", 3): {("0", "0"): 2}}, gate.read_branches(lcov, "/repo"))


class MergeTest(unittest.TestCase):

    def test_a_branch_is_taken_when_any_report_took_it(self):
        local = {("a.rs", 3): {("0", "0"): 1, ("0", "1"): 0}}
        test_server = {("a.rs", 3): {("0", "0"): 0, ("0", "1"): 4}}
        self.assertEqual({("a.rs", 3): {("0", "0"): 1, ("0", "1"): 4}},
                         gate.merge([local, test_server]))


class ChangedLinesTest(unittest.TestCase):

    def test_added_lines_of_each_file(self):
        diff = """diff --git a/a.rs b/a.rs
--- a/a.rs
+++ b/a.rs
@@ -3 +3,2 @@ fn f() {
@@ -10,0 +12 @@ fn g() {
diff --git a/gone.rs b/gone.rs
--- a/gone.rs
+++ /dev/null
@@ -1,4 +0,0 @@
"""
        self.assertEqual({"a.rs": {3, 4, 12}}, gate.changed_lines(diff))

    def test_a_hunk_that_only_deletes_adds_no_lines(self):
        diff = "--- a/a.rs\n+++ b/a.rs\n@@ -5,2 +4,0 @@\n"
        self.assertEqual({"a.rs": set()}, gate.changed_lines(diff))


class MainTest(unittest.TestCase):
    """The gate against a real git repository with one changed line."""

    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.git("init", "-q", "-b", "main")
        (self.repo / "a.rs").write_text("fn f(x: u8) -> u8 {\n    1\n}\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "base")
        (self.repo / "a.rs").write_text("fn f(x: u8) -> u8 {\n    if x > 0 { 1 } else { 2 }\n}\n")
        self.git("commit", "-q", "-am", "change")

    def git(self, *args):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
                       cwd=self.repo, check=True)

    def run_gate(self, *lcovs, exclude=()):
        paths = []
        for i, text in enumerate(lcovs):
            path = self.repo / ("%d.lcov" % i)
            path.write_text(text)
            paths.append(str(path))
        args = ["--base", "HEAD~1", "--root", str(self.repo)]
        for glob in exclude:
            args += ["--exclude", glob]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = gate.main(args + paths)
        return status, out.getvalue()

    def test_passes_when_every_branch_of_a_changed_line_was_taken(self):
        status, out = self.run_gate("SF:a.rs\nBRDA:2,0,0,1\nBRDA:2,0,1,3\nend_of_record\n")
        self.assertEqual(0, status, out)
        self.assertIn("Branches taken: 2 of 2.", out)

    def test_fails_on_a_changed_line_with_an_untaken_branch(self):
        status, out = self.run_gate("SF:a.rs\nBRDA:2,0,0,1\nBRDA:2,0,1,0\nend_of_record\n")
        self.assertEqual(1, status)
        self.assertIn("::error file=a.rs,line=2::1 of 2 branches", out)

    def test_two_reports_that_each_take_one_branch_pass_together(self):
        status, out = self.run_gate("SF:a.rs\nBRDA:2,0,0,1\nBRDA:2,0,1,0\nend_of_record\n",
                                    "SF:a.rs\nBRDA:2,0,0,0\nBRDA:2,0,1,1\nend_of_record\n")
        self.assertEqual(0, status, out)

    def test_an_untaken_branch_on_an_unchanged_line_passes(self):
        status, out = self.run_gate("SF:a.rs\nBRDA:1,0,0,0\nend_of_record\n")
        self.assertEqual(0, status, out)

    def test_an_excluded_file_passes(self):
        status, out = self.run_gate("SF:a.rs\nBRDA:2,0,0,0\nend_of_record\n", exclude=["a.*"])
        self.assertEqual(0, status, out)

    def test_fails_when_no_report_has_branch_records(self):
        status, out = self.run_gate("SF:a.rs\nDA:2,1\nend_of_record\n")
        self.assertEqual(1, status)
        self.assertIn("no report has branch records", out)


if __name__ == "__main__":
    unittest.main()
