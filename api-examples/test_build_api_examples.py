"""Run with: python3 -m unittest discover -s api-examples"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import build_api_examples as builder


def setter(way_id, option):
    return {"id": way_id, "option": option, "kind": "setter", "signature": "..."}


def surface(*ways, api="aws-kms-keyring"):
    return {"schema": 1, "language": "rust", "library": "mpl",
            "apis": [{"id": api, "group": "Keyrings", "name": "AWS KMS keyring",
                      "type": "aws_mpl::AwsKmsKeyring", "ways": list(ways)}]}


def marker(fields, code="let keyring = builder.kms_key_id(arn);"):
    return f"""    setup();
    // api-example: {fields}
    // snippet-start
    {code}
    // snippet-end
    assert_ok(keyring);
"""


class BuilderTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name).resolve()
        self.cwd = os.getcwd()
        os.chdir(self.root)

    def tearDown(self):
        os.chdir(self.cwd)
        self.dir.cleanup()

    def run_builder(self, surface_doc, tests):
        """Write surface.json and tests/<name> files, run main, return (exit code, output doc, stdout)."""
        (self.root / "surface.json").write_text(json.dumps(surface_doc))
        for name, text in tests.items():
            path = self.root / "tests" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        (self.root / "tests").mkdir(exist_ok=True)
        out = io.StringIO()
        with redirect_stdout(out):
            code = builder.main(["--surface", "surface.json", "--src", "tests", "--repo", "aws/r",
                                 "--commit", "abc", "--out", "api-examples.json"])
        return code, json.loads((self.root / "api-examples.json").read_text()), out.getvalue()

    def whys(self, doc):
        return {(f["api"], f["way"], f["why"]) for f in doc["uncovered"]}

    def test_empty_surface_passes(self):
        code, doc, _ = self.run_builder({"schema": 1, "language": "java", "library": "mpl", "apis": []}, {})
        self.assertEqual(code, 0)
        self.assertEqual(doc["apis"], [])
        self.assertEqual(doc["uncovered"], [])

    def test_covered_setter_records_snippet_and_required(self):
        code, doc, _ = self.run_builder(surface(setter("kms_key_id", "kmsKeyId")), {
            "kms.rs": marker("api=aws-kms-keyring way=kms_key_id takes=String kind=pass")
                      + marker("api=aws-kms-keyring way=kms_key_id kind=missing", "let r = builder.build();"),
        })
        self.assertEqual(code, 0, doc["uncovered"])
        way = doc["apis"][0]["ways"][0]
        self.assertTrue(way["required"])
        self.assertEqual(way["examples"][0], {"kind": "pass", "takes": "String",
                                              "code": "let keyring = builder.kms_key_id(arn);",
                                              "file": "tests/kms.rs", "line": 4})
        self.assertEqual((doc["repo"], doc["commit"]), ("aws/r", "abc"))

    def test_way_without_pass_snippet_fails(self):
        code, doc, out = self.run_builder(surface({"id": "builder", "option": None, "kind": "constructor"}), {})
        self.assertEqual(code, 1)
        self.assertIn(("aws-kms-keyring", "builder", "no pass snippet"), self.whys(doc))
        self.assertIn("aws-kms-keyring builder: no pass snippet", out)

    def test_overload_without_matching_takes_fails(self):
        way = {"id": "wrappingKey", "option": "wrappingKey", "kind": "method",
               "overloads": ["byte[]", "SecretKey"]}
        code, doc, _ = self.run_builder(surface(way), {
            "Raw.java": marker("api=aws-kms-keyring way=wrappingKey takes=byte[] kind=pass"),
        })
        self.assertEqual(code, 1)
        self.assertEqual(self.whys(doc),
                         {("aws-kms-keyring", "wrappingKey", "no pass snippet with takes=SecretKey")})

    def test_setter_without_missing_or_omitted_fails(self):
        code, doc, _ = self.run_builder(surface(setter("grant_tokens", "grantTokens")), {
            "kms.rs": marker("api=aws-kms-keyring way=grant_tokens takes=Vec<String> kind=pass"),
        })
        self.assertEqual(code, 1)
        self.assertEqual(self.whys(doc), {("aws-kms-keyring", "grant_tokens",
                                           "no missing or omitted snippet, so required is unknown")})

    def test_omitted_snippet_on_one_way_marks_shared_option_optional(self):
        code, doc, _ = self.run_builder(surface(setter("grant_tokens", "grantTokens"),
                                                setter("set_grant_tokens", "grantTokens")), {
            "kms.rs": marker("api=aws-kms-keyring way=grant_tokens takes=Vec<String> kind=pass")
                      + marker("api=aws-kms-keyring way=set_grant_tokens takes=Option<Vec<String>> kind=pass")
                      + marker("api=aws-kms-keyring way=grant_tokens kind=omitted"),
        })
        self.assertEqual(code, 0, doc["uncovered"])
        self.assertEqual([w["required"] for w in doc["apis"][0]["ways"]], [False, False])

    def test_missing_and_omitted_on_one_option_fails(self):
        code, doc, _ = self.run_builder(surface(setter("kms_key_id", "kmsKeyId")), {
            "kms.rs": marker("api=aws-kms-keyring way=kms_key_id takes=String kind=pass")
                      + marker("api=aws-kms-keyring way=kms_key_id kind=missing")
                      + marker("api=aws-kms-keyring way=kms_key_id kind=omitted"),
        })
        self.assertEqual(code, 1)
        self.assertEqual(self.whys(doc), {("aws-kms-keyring", "kms_key_id",
                                           "both missing and omitted snippets, so required is unclear")})

    def test_marker_for_unknown_way_fails(self):
        code, doc, _ = self.run_builder({"schema": 1, "language": "rust", "library": "mpl", "apis": []}, {
            "old.rs": marker("api=aws-kms-keyring way=gone takes=String kind=pass"),
        })
        self.assertEqual(code, 1)
        [failure] = doc["uncovered"]
        self.assertEqual((failure["api"], failure["way"], failure["file"], failure["line"]),
                         ("aws-kms-keyring", "gone", "tests/old.rs", 4))

    def test_malformed_markers_fail(self):
        code, doc, _ = self.run_builder({"schema": 1, "language": "rust", "library": "mpl", "apis": []}, {
            "a.rs": "// api-example: api=x way=y kind=pass takes=String\nlet a = 1;\n",
            "b.rs": "// api-example: api=x way=y kind=pass takes=String\n// snippet-start\nlet a = 1;\n",
            "c.rs": marker("api=x way=y kind=pass"),
            "d.rs": marker("api=x way=y kind=fine takes=String"),
        })
        self.assertEqual(code, 1)
        self.assertEqual(sorted((f["file"], f["why"]) for f in doc["uncovered"]), [
            ("tests/a.rs", "no // snippet-start on the line after the marker"),
            ("tests/b.rs", "no // snippet-end before the next marker or end of file"),
            ("tests/c.rs", "kind=pass needs takes="),
            ("tests/d.rs", "kind=fine is not one of missing, omitted, pass, reject"),
        ])


if __name__ == "__main__":
    unittest.main()
