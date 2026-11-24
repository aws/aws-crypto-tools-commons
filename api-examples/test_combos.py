"""Run with: python3 -m unittest discover -s api-examples"""

import io
import itertools
import json
import unittest
from contextlib import redirect_stdout, redirect_stderr

import combos
from test_build_api_examples import (API, TempDirTest, frame, fragment, left_out, setter, surface,
                                     together)

TEMPLATE = """notes
@@ file
// generated
{{tests}}
@@ test
fn {{name}}() {
    {{code}}
    {{check}}
}
@@ ok
ok();
@@ fails-with
fails_with({{error}});
@@ fails
fails();
"""


class GenerateTest(TempDirTest):

    def generate(self, ways, tests, cap=200):
        (self.root / "surface.json").write_text(json.dumps(surface(*ways)))
        (self.root / "combos.template").write_text(TEMPLATE)
        self.write_tests(tests)
        out = io.StringIO()
        with redirect_stdout(out):
            code = combos.main(["generate", "--surface", "surface.json", "--src", "tests",
                                "--template", "combos.template", "--out", "gen/combos.rs",
                                "--manifest", "combos.json", "--cap", str(cap)])
        self.assertEqual(code, 0)
        manifest = json.loads((self.root / "combos.json").read_text())
        return {a["api"]: a for a in manifest["apis"]}[API], out.getvalue()

    def test_every_call_gets_a_test_with_the_right_check(self):
        api, out = self.generate([setter("key_name", "keyName"), setter("set_key_name", "keyName"),
                                  setter("ttl", "ttl")], {
            "raw.rs": frame(setup=["let client = Client::default();"])
                      + fragment("key_name", "a string", ".key_name(\"x\")", "default", setup=["let x = 1;"])
                      + fragment("key_name", "an empty string", ".key_name(\"\")", "fails=validation")
                      + fragment("set_key_name", "a string", ".set_key_name(Some(x))", "alt")
                      + left_out("key_name", "fails=missing")
                      + fragment("ttl", "zero", ".ttl(0)", "fails=range") + fragment("ttl", "a number", ".ttl(5)")
                      + left_out("ttl"),
        })
        # key_name: left out, a string, an empty string. ttl: left out, zero, a number. The alt is not a choice.
        self.assertEqual((api["mode"], api["total"], len(api["combos"])), ("all", 9, 9))
        by_choices = {(c["choices"]["keyName"], c["choices"]["ttl"]): (c["expect"], c["error"]) for c in api["combos"]}
        self.assertEqual(by_choices[("a string", None)], ("ok", None))
        self.assertEqual(by_choices[("a string", "a number")], ("ok", None))
        self.assertEqual(by_choices[(None, None)], ("fails", "missing"))
        self.assertEqual(by_choices[("a string", "zero")], ("fails", "range"))
        self.assertEqual(by_choices[("an empty string", "zero")], ("fails", None))
        self.assertIn(f"{API}: 9 calls (all, 9 possible)", out)

        code = (self.root / "gen" / "combos.rs").read_text()
        name = next(c["name"] for c in api["combos"] if c["choices"] == {"keyName": "a string", "ttl": "zero"})
        self.assertIn(f"""fn {name}() {{
    let client = Client::default();
    let x = 1;
    let keyring = RawAesKeyring::builder()
        .key_name("x")
        .ttl(0)
        .build()?;
    fails_with(range);
}}""", code)
        self.assertTrue(code.startswith("// generated\nfn raw_aes_keyring_001() {"))

    def test_one_of_group_fails_with_none_or_both_set(self):
        api, _ = self.generate([setter("keyring", "keyring"), setter("cmm", "cmm")], {
            "e.rs": frame("one-of=keyring,cmm")
                    + fragment("keyring", "a keyring", ".keyring(k)", "default") + left_out("keyring")
                    + fragment("cmm", "a CMM", ".cmm(c)") + left_out("cmm")
                    + left_out("keyring,cmm", "fails=no_keyring") + together("keyring,cmm", "two_keyrings"),
        })
        self.assertEqual({(c["choices"]["keyring"], c["choices"]["cmm"]): c["error"] for c in api["combos"]}, {
            (None, None): "no_keyring", ("a keyring", "a CMM"): "two_keyrings",
            ("a keyring", None): None, (None, "a CMM"): None})

    def test_above_the_cap_a_pairwise_sample_holds_the_starting_call(self):
        ways = [setter(f"o{i}", f"o{i}") for i in range(5)]
        blocks = frame()
        for i in range(5):
            blocks += "".join(fragment(f"o{i}", f"have {v}", f".o{i}({v})", "default" if v == 2 else "")
                              for v in range(3)) + left_out(f"o{i}")
        api, out = self.generate(ways, {"raw.rs": blocks}, cap=100)
        self.assertEqual((api["mode"], api["total"]), ("pairwise", 4 ** 5))
        self.assertLess(len(api["combos"]), 100)
        self.assertEqual(api["combos"][0]["choices"], {f"o{i}": "have 2" for i in range(5)})
        rows = [tuple(c["choices"][f"o{i}"] for i in range(5)) for c in api["combos"]]
        values = [None] + [f"have {v}" for v in range(3)]
        for i, j in itertools.combinations(range(5), 2):
            for a, b in itertools.product(values, values):
                self.assertTrue(any(r[i] == a and r[j] == b for r in rows), (i, a, j, b))


class RecordTest(TempDirTest):

    def test_records_libtest_outcomes_and_fails_when_one_is_missing(self):
        (self.root / "combos.json").write_text(json.dumps({"schema": 1, "apis": [{"api": API, "combos": [
            {"name": "raw_aes_keyring_001"}, {"name": "raw_aes_keyring_002"}]}]}))
        (self.root / "test.log").write_text("test raw_aes_keyring_001 ... ok\ntest raw_aes_keyring_002 ... FAILED\n")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(combos.main(["record", "--manifest", "combos.json", "--libtest", "test.log"]), 0)
        doc = json.loads((self.root / "combos.json").read_text())
        self.assertEqual([c["outcome"] for c in doc["apis"][0]["combos"]], ["pass", "fail"])

        (self.root / "test.log").write_text("test raw_aes_keyring_001 ... ok\n")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(combos.main(["record", "--manifest", "combos.json", "--libtest", "test.log"]), 1)

    def test_records_junit_outcomes(self):
        (self.root / "combos.json").write_text(json.dumps({"schema": 1, "apis": [{"api": API, "combos": [
            {"name": "rawAesKeyring001"}]}]}))
        (self.root / "results").mkdir()
        (self.root / "results" / "TEST-Combos.xml").write_text(
            '<testsuite><testcase name="rawAesKeyring001()"/></testsuite>')
        with redirect_stdout(io.StringIO()):
            self.assertEqual(combos.main(["record", "--manifest", "combos.json", "--junit", "results"]), 0)
        doc = json.loads((self.root / "combos.json").read_text())
        self.assertEqual(doc["apis"][0]["combos"][0]["outcome"], "pass")


if __name__ == "__main__":
    unittest.main()
