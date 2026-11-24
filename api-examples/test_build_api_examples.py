"""Run with: python3 -m unittest discover -s api-examples"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import build_api_examples as builder
import smithy_names


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


class TempDirTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name).resolve()
        self.cwd = os.getcwd()
        os.chdir(self.root)

    def tearDown(self):
        os.chdir(self.cwd)
        self.dir.cleanup()

    def run_builder(self, surface_doc, tests, names=None):
        """Write surface.json, names.json and tests/<name> files, run main.

        names is {api id: entry} for the surface's library. Returns (exit code, output doc, stdout).
        """
        (self.root / "surface.json").write_text(json.dumps(surface_doc))
        (self.root / "names.json").write_text(json.dumps({"libraries": {"mpl": names or {}}}))
        for name, text in tests.items():
            path = self.root / "tests" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        (self.root / "tests").mkdir(exist_ok=True)
        out = io.StringIO()
        with redirect_stdout(out):
            code = builder.main(["--surface", "surface.json", "--src", "tests", "--repo", "aws/r",
                                 "--commit", "abc", "--out", "api-examples.json", "--names", "names.json"])
        return code, json.loads((self.root / "api-examples.json").read_text()), out.getvalue()


class BuilderTest(TempDirTest):

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


def names_entry(members=(), operations=(), aliases=None):
    return {"shape": "ns#Input", "members": list(members), "operations": list(operations),
            "aliases": aliases or {}}


def covered(*way_ids):
    """Markers that fully cover setter ways."""
    return "".join(marker(f"api=aws-kms-keyring way={w} takes=String kind=pass")
                   + marker(f"api=aws-kms-keyring way={w} kind=missing") for w in way_ids)


class RowTest(TempDirTest):

    def rows(self, doc):
        return [(r["key"], r["kind"]) for r in doc["apis"][0]["rows"]]

    def way_rows(self, doc):
        return {w["id"]: w["row"] for w in doc["apis"][0]["ways"]}

    def test_rust_setter_pair_lands_on_the_smithy_member_row(self):
        code, doc, _ = self.run_builder(
            surface(setter("kms_key_id", "kmsKeyId"), setter("set_kms_key_id", "kmsKeyId")),
            {"kms.rs": covered("kms_key_id", "set_kms_key_id")},
            {"aws-kms-keyring": names_entry(["kmsKeyId"])})
        self.assertEqual(code, 0, doc["uncovered"])
        self.assertEqual(self.way_rows(doc), {"kms_key_id": "kmsKeyId", "set_kms_key_id": "kmsKeyId"})

    def test_option_matches_member_that_differs_only_in_underscores(self):
        code, doc, _ = self.run_builder(
            surface(setter("set_net_v4_0_0_retry_policy", "netV400RetryPolicy")),
            {"kms.rs": covered("set_net_v4_0_0_retry_policy")},
            {"aws-kms-keyring": names_entry(["netV4_0_0_RetryPolicy"])})
        self.assertEqual(self.way_rows(doc), {"set_net_v4_0_0_retry_policy": "netV4_0_0_RetryPolicy"})

    def test_alias_maps_a_renamed_option_to_its_member(self):
        code, doc, _ = self.run_builder(surface(setter("ttl", "ttl")), {"kms.rs": covered("ttl")},
                                        {"aws-kms-keyring": names_entry(["ttlSeconds"], aliases={"ttl": "ttlSeconds"})})
        self.assertEqual(self.way_rows(doc), {"ttl": "ttlSeconds"})
        self.assertEqual(self.rows(doc), [("construct", "construct"), ("ttlSeconds", "member")])

    def test_every_constructor_way_lands_on_the_construct_row(self):
        ways = [{"id": i, "option": None, "kind": "constructor"} for i in ("builder", "from_conf", "default")]
        code, doc, _ = self.run_builder(surface(*ways), {
            "c.rs": "".join(marker(f"api=aws-kms-keyring way={i} takes=Config kind=pass") for i in
                            ("builder", "from_conf", "default")),
        }, {"aws-kms-keyring": names_entry(["kmsKeyId"])})
        self.assertEqual(set(self.way_rows(doc).values()), {"construct"})

    def test_method_lands_on_its_operation_row_and_api_has_no_construct_row(self):
        code, doc, _ = self.run_builder(
            surface({"id": "encrypt", "option": None, "kind": "method"}, setter("plaintext", "plaintext")), {
                "e.rs": marker("api=aws-kms-keyring way=encrypt takes=Vec<u8> kind=pass") + covered("plaintext"),
            }, {"aws-kms-keyring": names_entry(["plaintext", "keyring"], ["Encrypt"])})
        self.assertEqual(code, 0, doc["uncovered"])
        self.assertEqual(self.way_rows(doc), {"encrypt": "Encrypt", "plaintext": "plaintext"})
        self.assertEqual(self.rows(doc), [("Encrypt", "operation"), ("plaintext", "member"), ("keyring", "member")])

    def test_rows_follow_model_order_and_keep_members_no_way_offers(self):
        code, doc, _ = self.run_builder(surface(setter("key_name", "keyName"), setter("key_namespace", "keyNamespace")),
                                        {"kms.rs": covered("key_name", "key_namespace")},
                                        {"aws-kms-keyring": names_entry(["keyNamespace", "wrappingKey", "keyName"])})
        self.assertEqual(self.rows(doc), [("construct", "construct"), ("keyNamespace", "member"),
                                          ("wrappingKey", "member"), ("keyName", "member")])

    def test_option_not_in_the_model_is_an_extra_row_and_does_not_fail(self):
        code, doc, _ = self.run_builder(surface(setter("grant_tokens", "grantTokens"), setter("set_grant_tokens", "grantTokens")),
                                        {"kms.rs": covered("grant_tokens", "set_grant_tokens")},
                                        {"aws-kms-keyring": names_entry(["kmsKeyId"])})
        self.assertEqual(code, 0, doc["uncovered"])
        self.assertEqual(self.way_rows(doc), {"grant_tokens": "extra:grantTokens", "set_grant_tokens": "extra:grantTokens"})
        self.assertEqual(self.rows(doc), [("construct", "construct"), ("kmsKeyId", "member"),
                                          ("extra:grantTokens", "extra")])

    def test_api_missing_from_names_file_has_construct_and_extra_rows(self):
        code, doc, _ = self.run_builder(surface(setter("kms_key_id", "kmsKeyId")), {"kms.rs": covered("kms_key_id")})
        self.assertEqual(self.rows(doc), [("construct", "construct"), ("extra:kmsKeyId", "extra")])


class SmithyNamesTest(unittest.TestCase):

    def test_maps_operations_to_apis_like_the_conformance_config(self):
        mp = "aws.cryptography.materialProviders"
        shapes = {
            f"{mp}#Mpl": {"type": "service", "operations": [{"target": f"{mp}#{o}"} for o in (
                "CreateAwsKmsHierarchicalKeyring", "CreateAwsKmsKeyring", "GetAlgorithmSuiteInfo", "ValidThing")]},
            f"{mp}#CreateAwsKmsHierarchicalKeyring": {"type": "operation", "input": {"target": f"{mp}#HInput"}},
            f"{mp}#CreateAwsKmsKeyring": {"type": "operation", "input": {"target": f"{mp}#KInput"}},
            f"{mp}#GetAlgorithmSuiteInfo": {"type": "operation", "input": {"target": f"{mp}#GInput"}},
            f"{mp}#ValidThing": {"type": "operation", "input": {"target": f"{mp}#VInput"}},
            f"{mp}#HInput": {"type": "structure", "members": {"branchKeyId": {}, "ttlSeconds": {}}},
            f"{mp}#KInput": {"type": "structure", "members": {"kmsKeyId": {}}},
            f"{mp}#VInput": {"type": "structure", "members": {"thing": {}}},
        }
        config = {"rename": [
            {"shape": f"{mp}#CreateAwsKmsHierarchicalKeyring", "rust": "HierarchicalKeyring::builder"},
            {"shape": f"{mp}#HInput$ttlSeconds", "rust": "ttl"},
            {"shape": f"{mp}#GetAlgorithmSuiteInfo", "rust": "AlgorithmSuiteId::specification"},
        ]}
        self.assertEqual(smithy_names.names(shapes, config)["mpl"], {
            "hierarchical-keyring": {"shape": f"{mp}#HInput", "members": ["branchKeyId", "ttlSeconds"],
                                     "operations": [], "aliases": {"ttl": "ttlSeconds"}},
            "aws-kms-keyring": {"shape": f"{mp}#KInput", "members": ["kmsKeyId"], "operations": [], "aliases": {}},
            "valid-thing": {"shape": f"{mp}#VInput", "members": ["thing"], "operations": ["ValidThing"],
                            "aliases": {}},
        })


if __name__ == "__main__":
    unittest.main()
