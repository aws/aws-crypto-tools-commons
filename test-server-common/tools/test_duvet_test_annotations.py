"""Run with: python3 -m unittest discover -s test-server-common/tools"""

import json
import tempfile
import unittest
from pathlib import Path

import duvet_test_annotations as picker

TESTS = '''package x;

class SampleTests {

    private static void helper(LanguageServerTarget target) {
        //= spec/doc.md#sec
        //= type=test
        //# Helpers MUST count.
        EsdkOps.encrypt(target.endpoint());
    }

    @ParameterizedTest(name = "runs {0}")
    @MethodSource("targets")
    void runs(LanguageServerTarget target) {
        //= spec/doc.md#sec
        //= type=test
        //# The thing MUST be blue.
        EsdkOps.encrypt(target.endpoint());
    }

    @Test
    void skipped() {
        //= spec/doc.md#sec
        //= type=test
        //# The box MUST be red.
        FeatureGate.require(Set.of("caching"), target);
    }

    @Test
    void knownBug() {
        //= spec/doc.md#sec
        //= type=test
        //# The lid MUST be green.
        KnownBugGate.gateDeclared(
            "lid-is-grey", target, () -> {});
    }

    @Test
    void callsHelper() {
        helper(target);
    }

    @Test
    void wrongQuote() {
        //= spec/doc.md#sec
        //= type=test
        //# The thing MUST be purple.
        EsdkOps.encrypt(target.endpoint());
    }
}
'''

SPEC = """# Doc

## Sec

The thing MUST be blue.
The box MUST be red.
The lid MUST be green.
Helpers MUST count.
"""


def gate_line(method, result="would-run"):
    return json.dumps({
        "id": f"[engine:junit-jupiter]/[class:x.SampleTests]/[test-template:{method}(x.T)]"
              "/[test-template-invocation:#1]",
        "name": method, "targets": [], "features": [], "result": result})


class PickerTest(unittest.TestCase):

    def run_picker(self, tests=TESTS, extra_args=()):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (root / "tests").mkdir()
        (root / "tests" / "SampleTests.java").write_text(tests)
        (root / "spec").mkdir()
        (root / "spec" / "doc.md").write_text(SPEC)
        (root / "gate.jsonl").write_text("\n".join([
            gate_line("runs"), gate_line("skipped", "skipped"), gate_line("knownBug"),
            gate_line("callsHelper"), gate_line("wrongQuote")]) + "\n")
        (root / "bugs.json").write_text('["lid-is-grey"]')
        out = root / "out" / "esdk.java"
        code = picker.main([
            "--gate-log", str(root / "gate.jsonl"), "--tests-dir", str(root / "tests"),
            "--bug-config", str(root / "bugs.json"), "--spec-root", str(root),
            "--out", str(out), *extra_args])
        return code, out.read_text() if out.exists() else ""

    def test_keeps_only_annotations_whose_test_runs_cleanly(self):
        code, out = self.run_picker()
        self.assertEqual(0, code)
        self.assertIn("//# The thing MUST be blue.", out)
        self.assertIn("//# Helpers MUST count.", out)
        self.assertNotIn("The box MUST be red.", out)
        self.assertNotIn("The lid MUST be green.", out)
        self.assertNotIn("purple", out)

    def test_rewrites_the_spec_prefix(self):
        tests = TESTS.replace("//= spec/doc.md", "//= specification/doc.md")
        code, out = self.run_picker(tests, ["--prefix", "specification/=spec/"])
        self.assertEqual(0, code)
        self.assertIn("//= spec/doc.md#sec", out)
        self.assertNotIn("specification/", out)

    def test_refuses_an_implementation_annotation(self):
        tests = TESTS.replace("//= type=test\n        //# The thing MUST be blue.",
                              "//# The thing MUST be blue.", 1)
        code, _ = self.run_picker(tests)
        self.assertEqual(1, code)


if __name__ == "__main__":
    unittest.main()
