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
Every keyring MUST pass.
Every keyring MUST also pass this.
The keyring MAY skip this.
"""

CONTRACT = '''package x;

interface Contract {

    @KeyringTest
    default void inherited(Mpl mpl) {
        //= spec/doc.md#sec
        //= type=test
        //# Every keyring MUST pass.
        mpl.check();
    }

    @KeyringTest
    default void overridden(Mpl mpl) {
        //= spec/doc.md#sec
        //= type=test
        //# Every keyring MUST also pass this.
        mpl.check();
    }
}
'''

KEYRING_TESTS = '''package x;

@KeyringFeature("raw-aes")
public class KeyringTests implements KeyringTestDefaults, Contract {

    @Override
    @KeyringTest
    public void overridden(Mpl mpl) {
        //= spec/doc.md#sec
        //= type=test
        //# The thing MUST be blue.
        Contract.super.overridden(mpl);
    }
}
'''

CONTRACT_EXCEPTION = '''
    @Override
    @KeyringTest
    @ContractException(reason = "this keyring may skip it")
    public void inherited(Mpl mpl) {
        //= spec/doc.md#sec
        //= type=exception
        //= reason=this keyring may skip it
        //# The keyring MAY skip this.
    }
}
'''


def gate_line(method, result="would-run", cls="SampleTests"):
    return json.dumps({
        "id": f"[engine:junit-jupiter]/[class:x.{cls}]/[test-template:{method}(x.T)]"
              "/[test-template-invocation:#1]",
        "name": method, "targets": [], "features": [], "result": result})


class PickerTest(unittest.TestCase):

    def run_picker(self, tests=TESTS, extra_args=(), files=None, gate_lines=()):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (root / "tests").mkdir()
        (root / "tests" / "SampleTests.java").write_text(tests)
        for name, text in (files or {}).items():
            (root / "tests" / name).write_text(text)
        (root / "spec").mkdir()
        (root / "spec" / "doc.md").write_text(SPEC)
        (root / "gate.jsonl").write_text("\n".join([
            gate_line("runs"), gate_line("skipped", "skipped"), gate_line("knownBug"),
            gate_line("callsHelper"), gate_line("wrongQuote"), *gate_lines]) + "\n")
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

    def test_reads_keyring_tests_and_their_known_bugs(self):
        tests = TESTS.replace('@ParameterizedTest(name = "runs {0}")\n    @MethodSource("targets")',
                              '@KeyringTest(feature = "raw-aes", name = "runs {0}")', 1)
        tests = tests.replace("KnownBugGate.gateDeclared(", "mpl.knownBug(", 1)
        code, out = self.run_picker(tests)
        self.assertEqual(0, code)
        self.assertIn("//# The thing MUST be blue.", out)
        self.assertNotIn("The lid MUST be green.", out)

    def test_reads_a_known_bug_named_after_the_check(self):
        tests = TESTS.replace('KnownBugGate.gateDeclared(\n            "lid-is-grey", target, () -> {});',
                              'keyring.onDecryptFailsWith(materials, edks, ERROR)\n'
                              '            .unlessKnownBug("lid-is-grey");', 1)
        self.assertIn("unlessKnownBug", tests)
        code, out = self.run_picker(tests)
        self.assertEqual(0, code)
        self.assertIn("//# The thing MUST be blue.", out)
        self.assertNotIn("The lid MUST be green.", out)

    def test_credits_a_default_method_only_when_the_class_does_not_override_it(self):
        code, out = self.run_picker(
            files={"Contract.java": CONTRACT, "KeyringTests.java": KEYRING_TESTS},
            gate_lines=[gate_line("inherited", cls="KeyringTests"), gate_line("overridden", cls="KeyringTests")])
        self.assertEqual(0, code)
        self.assertIn("// Contract#inherited\n//= spec/doc.md#sec\n//= type=test\n//# Every keyring MUST pass.", out)
        self.assertIn("// KeyringTests#overridden\n//= spec/doc.md#sec\n//= type=test\n//# The thing MUST be blue.", out)
        self.assertNotIn("Every keyring MUST also pass this.", out)

    def test_keeps_an_exception_annotation_whose_test_is_skipped(self):
        tests = KEYRING_TESTS.rstrip().removesuffix("}") + CONTRACT_EXCEPTION
        code, out = self.run_picker(
            files={"Contract.java": CONTRACT, "KeyringTests.java": tests},
            gate_lines=[gate_line("inherited", "skipped", cls="KeyringTests")])
        self.assertEqual(0, code)
        self.assertIn("//= type=exception\n//= reason=this keyring may skip it\n//# The keyring MAY skip this.", out)
        self.assertNotIn("Every keyring MUST pass.", out)

    def test_refuses_an_implementation_annotation(self):
        tests = TESTS.replace("//= type=test\n        //# The thing MUST be blue.",
                              "//# The thing MUST be blue.", 1)
        code, _ = self.run_picker(tests)
        self.assertEqual(1, code)


if __name__ == "__main__":
    unittest.main()
