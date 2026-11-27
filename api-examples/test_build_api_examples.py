"""Run with: python3 -m unittest discover -s api-examples"""

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

import build_api_examples as builder
import smithy_names

API = "raw-aes-keyring"
PHRASES = json.loads(builder.Path(builder.__file__).with_name("type-phrases.json").read_text())["phrases"]
BUILDER = {"id": "CreateRawAesKeyring", "option": None, "kind": "constructor",
           "signature": "materialProviders.CreateRawAesKeyring(CreateRawAesKeyringInput)"}


def take(t, sig):
    return {"type": t, "signature": sig}


def setter(way_id, option, *takes):
    return {"id": way_id, "option": option, "kind": "setter", "signature": "...", "takes": list(takes)}


def names_entry(members=(), operations=(), aliases=None):
    return {"shape": "ns#Input", "members": list(members), "operations": list(operations), "aliases": aliases or {}}


def shipped(*ways, names=None):
    """The document build_shipped writes for one Java Raw AES keyring API with these ways."""
    s = {"schema": 1, "language": "java", "library": "mpl", "shipped": {"package": "p", "version": "1.11.1"},
         "apis": [{"id": API, "group": "Keyrings", "name": "Raw AES keyring", "type": "T", "ways": list(ways)}]}
    return builder.build_shipped(s, {API: names} if names else {}, PHRASES, "aws/aws-crypto-tools-commons", "abc",
                                 {"id": 1, "attempt": 1})


class RowTest(unittest.TestCase):

    def rows(self, doc):
        return [(r["key"], r["kind"]) for r in doc["apis"][0]["rows"]]

    def way_rows(self, doc):
        return {w["id"]: w["row"] for w in doc["apis"][0]["ways"]}

    def test_setters_for_one_option_land_on_the_smithy_member_row(self):
        doc = shipped(BUILDER, setter("keyName", "keyName"), setter("KeyName", "KeyName"),
                      names=names_entry(["keyName"]))
        self.assertEqual(self.way_rows(doc), {"CreateRawAesKeyring": "construct", "keyName": "keyName",
                                              "KeyName": "keyName"})

    def test_option_matches_member_that_differs_only_in_underscores(self):
        doc = shipped(setter("netV4_0_0_RetryPolicy", "netV400RetryPolicy"),
                      names=names_entry(["netV4_0_0_RetryPolicy"]))
        self.assertEqual(self.way_rows(doc)["netV4_0_0_RetryPolicy"], "netV4_0_0_RetryPolicy")

    def test_alias_maps_a_renamed_option_to_its_member(self):
        doc = shipped(BUILDER, setter("ttl", "ttl"), names=names_entry(["ttlSeconds"], aliases={"ttl": "ttlSeconds"}))
        self.assertEqual(self.way_rows(doc)["ttl"], "ttlSeconds")
        self.assertEqual(self.rows(doc), [("construct", "construct"), ("ttlSeconds", "member")])

    def test_method_lands_on_its_operation_row_and_api_has_no_construct_row(self):
        encrypt = {"id": "encrypt", "option": None, "kind": "method", "signature": "..."}
        doc = shipped(encrypt, setter("plaintext", "plaintext"), names=names_entry(["plaintext", "keyring"], ["Encrypt"]))
        self.assertEqual(self.way_rows(doc), {"encrypt": "Encrypt", "plaintext": "plaintext"})
        self.assertEqual(self.rows(doc), [("Encrypt", "operation"), ("plaintext", "member"), ("keyring", "member")])

    def test_rows_follow_model_order_and_list_haves_in_source_order(self):
        doc = shipped(BUILDER, setter("keyName", "keyName", take("java.lang.String", "keyName(String)"),
                                      take("java.nio.ByteBuffer", "keyName(ByteBuffer)")),
                      names=names_entry(["keyNamespace", "keyName"]))
        self.assertEqual({r["key"]: r["haves"] for r in doc["apis"][0]["rows"]}, {
            "construct": [], "keyNamespace": [], "keyName": ["a string", "a byte buffer"]})

    def test_option_not_in_the_model_is_an_extra_row(self):
        doc = shipped(BUILDER, setter("grantTokens", "grantTokens"), names=names_entry(["kmsKeyId"]))
        self.assertEqual(self.rows(doc), [("construct", "construct"), ("kmsKeyId", "member"),
                                          ("extra:grantTokens", "extra")])


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


class ShippedTest(unittest.TestCase):
    NAMES = names_entry(["keyNamespace", "keyName", "wrappingKey", "wrappingAlg"])

    def test_each_type_becomes_a_shipped_choice_named_by_the_phrase_table(self):
        doc = shipped(BUILDER,
                      setter("wrappingKey", "wrappingKey", take("java.nio.ByteBuffer", "wrappingKey(ByteBuffer)"),
                             take("byte[]", "wrappingKey(byte[])")),
                      setter("keyName", "keyName", take("java.lang.String", "keyName(String)"),
                             take("*string", "KeyName: string")),
                      names=self.NAMES)
        api = doc["apis"][0]
        self.assertEqual([(c["row"], c["have"], c["takes"], c["expect"]) for c in api["choices"]], [
            ("wrappingKey", "a byte buffer", "java.nio.ByteBuffer", "shipped"),
            ("wrappingKey", "bytes in memory", "byte[]", "shipped"),
            ("keyName", "a string", "java.lang.String | *string", "shipped"),
        ])
        self.assertEqual(api["choices"][0]["setter"], "wrappingKey(ByteBuffer)")
        self.assertTrue(api["shipped"])
        self.assertEqual(doc["shipped"]["version"], "1.11.1")
        self.assertEqual(doc["uncovered"], [])
        self.assertEqual(api["examples"][0]["code"], "materialProviders.CreateRawAesKeyring(CreateRawAesKeyringInput)")

    def test_a_type_that_the_table_does_not_list_shows_its_own_name(self):
        doc = shipped(BUILDER, setter("wrappingAlg", "wrappingAlg", take(
            "software.amazon.cryptography.materialproviders.model.AesWrappingAlg", "wrappingAlg(AesWrappingAlg)")),
            names=self.NAMES)
        self.assertEqual(doc["apis"][0]["choices"][0]["have"], "AesWrappingAlg")

    def test_the_phrase_table_names_the_usual_types(self):
        self.assertEqual({t: builder.have_of(t, PHRASES) for t in
                          ["byte[]", "bytes", "[]byte", "Uint8Array", "java.nio.ByteBuffer", "System.IO.MemoryStream",
                           "java.io.InputStream", "NodeJS.ReadableStream", "str", "String",
                           "java.util.Map<java.lang.String, java.lang.String>", "dict", "Int64?", "*int64"]}, {
            "byte[]": "bytes in memory", "bytes": "bytes in memory", "[]byte": "bytes in memory",
            "Uint8Array": "bytes in memory", "java.nio.ByteBuffer": "a byte buffer",
            "System.IO.MemoryStream": "a memory stream", "java.io.InputStream": "a stream",
            "NodeJS.ReadableStream": "a stream", "str": "a string", "String": "a string",
            "java.util.Map<java.lang.String, java.lang.String>": "a map", "dict": "a map", "Int64?": "a number",
            "*int64": "a number"})

    def test_no_type_is_in_the_phrase_table_twice(self):
        types = [t for ts in PHRASES.values() for t in ts]
        self.assertEqual(sorted({t for t in types if types.count(t) > 1}), [])

    def test_main_writes_the_document(self):
        with tempfile.TemporaryDirectory() as d:
            root = builder.Path(d)
            surface = {"schema": 1, "language": "java", "library": "mpl", "shipped": {"package": "p", "version": "1"},
                       "apis": [{"id": API, "ways": [setter("keyName", "keyName", take("java.lang.String", "keyName(String)"))]}]}
            (root / "surface.json").write_text(json.dumps(surface))
            (root / "names.json").write_text(json.dumps({"libraries": {"mpl": {API: names_entry(["keyName"])}}}))
            with redirect_stdout(StringIO()):
                code = builder.main(["--surface", str(root / "surface.json"), "--names", str(root / "names.json"),
                                     "--repo", "aws/r", "--commit", "abc", "--out", str(root / "out.json")])
            doc = json.loads((root / "out.json").read_text())
        self.assertEqual(code, 0)
        self.assertEqual(doc["apis"][0]["ways"][0]["row"], "keyName")


if __name__ == "__main__":
    unittest.main()
