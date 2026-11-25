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

API = "raw-aes-keyring"


def setter(way_id, option, **extra):
    return {"id": way_id, "option": option, "kind": "setter", "signature": "...", **extra}


BUILDER = {"id": "builder", "option": None, "kind": "constructor", "signature": "..."}


def surface(*ways, api=API):
    return {"schema": 1, "language": "rust", "library": "mpl",
            "apis": [{"id": api, "group": "Keyrings", "name": "Raw AES keyring",
                      "type": "aws_mpl::RawAesKeyring", "ways": [BUILDER, *ways]}]}


def frame(extra="", setup=()):
    lines = [f"    // api-example: api={API} frame way=builder {extra}".rstrip()]
    if setup:
        lines += [f"    {s}" for s in setup] + ["    // api-example: call"]
    lines += ["    let keyring = RawAesKeyring::builder()",
              "        // api-example: options",
              "        .key_name(\"name\")",
              "        // api-example: tail",
              "        .build()?;",
              "    // api-example: end",
              "    check(keyring);"]
    return "\n".join(lines) + "\n"


def fragment(way, have, line, fields="", setup=()):
    lines = [f"    // api-example: api={API} way={way} have=\"{have}\" {fields}".rstrip()]
    if setup:
        lines += [f"    {s}" for s in setup] + ["    // api-example: call"]
    lines += ["    let keyring = RawAesKeyring::builder()",
              "        // api-example: setter",
              f"        {line}",
              "        .build()?;",
              "    // api-example: end"]
    return "\n".join(lines) + "\n"


def left_out(ways, fields=""):
    return (f"    // api-example: api={API} way={ways} left-out {fields}".rstrip() + "\n"
            "    let result = RawAesKeyring::builder().build();\n"
            "    // api-example: end\n")


def together(ways, error):
    return (f"    // api-example: api={API} way={ways} together fails={error}\n"
            "    let result = RawAesKeyring::builder().a(1).b(2).build();\n"
            "    // api-example: end\n")


def required(way):
    """A required option with one default choice."""
    return (fragment(way, "a string", f".{way}(\"x\")", "default")
            + left_out(way, "fails=validation"))


def optional(way):
    return fragment(way, "a string", f".{way}(\"x\")") + left_out(way)


class TempDirTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name).resolve()
        self.cwd = os.getcwd()
        os.chdir(self.root)

    def tearDown(self):
        os.chdir(self.cwd)
        self.dir.cleanup()

    def write_tests(self, tests):
        (self.root / "tests").mkdir(exist_ok=True)
        for name, text in tests.items():
            (self.root / "tests" / name).write_text(text)

    def run_builder(self, surface_doc, tests, names=None, extra=()):
        """Write surface.json, names.json and tests/<name> files, run main.

        names is {api id: entry} for the surface's library. Returns (exit code, output doc, stdout).
        """
        (self.root / "surface.json").write_text(json.dumps(surface_doc))
        (self.root / "names.json").write_text(json.dumps({"libraries": {"mpl": names or {}}}))
        self.write_tests(tests)
        out = io.StringIO()
        with redirect_stdout(out):
            code = builder.main(["--surface", "surface.json", "--src", "tests", "--repo", "aws/r",
                                 "--commit", "abc", "--run-id", "7", "--run-attempt", "2",
                                 "--out", "api-examples.json", "--names", "names.json", *extra])
        return code, json.loads((self.root / "api-examples.json").read_text()), out.getvalue()


def whys(doc):
    return {(f["api"], f["way"], f["why"]) for f in doc["uncovered"]}


class BuilderTest(TempDirTest):

    def test_empty_surface_passes(self):
        code, doc, _ = self.run_builder({"schema": 1, "language": "java", "library": "mpl", "apis": []}, {})
        self.assertEqual(code, 0)
        self.assertEqual(doc["apis"], [])
        self.assertEqual(doc["uncovered"], [])

    def test_frame_and_fragment_record_their_parts(self):
        code, doc, _ = self.run_builder(surface(setter("key_name", "keyName")), {
            "raw.rs": frame(setup=["let esdk = Client::default();"])
                      + fragment("key_name", "a string from your config", ".key_name(key_name)",
                                 "takes=String default", setup=["let key_name: String = config().key_name;"])
                      + left_out("key_name", "fails=validation"),
        })
        self.assertEqual(code, 0, doc["uncovered"])
        api = doc["apis"][0]
        self.assertEqual(api["frame"], {"way": "builder", "setup": ["let esdk = Client::default();"],
                                        "head": ["let keyring = RawAesKeyring::builder()"],
                                        "tail": ["    .build()?;"], "one_of": [], "file": "tests/raw.rs", "line": 1})
        [choice] = api["choices"]
        self.assertEqual(choice, {
            "row": "extra:keyName", "way": "key_name", "have": "a string from your config",
            "setup": ["let key_name: String = config().key_name;"], "setter": "    .key_name(key_name)",
            "expect": "ok", "error": None, "default": True, "takes": "String", "alts": [],
            "file": "tests/raw.rs", "line": 11})
        self.assertEqual(api["left_out"], [{"rows": ["extra:keyName"], "expect": "fails", "error": "validation",
                                            "file": "tests/raw.rs", "line": 19}])
        self.assertTrue(api["ways"][1]["required"])
        self.assertEqual((doc["schema"], doc["repo"], doc["commit"], doc["run"]),
                         (4, "aws/r", "abc", {"id": 7, "attempt": 2}))

    def test_alt_is_shown_inside_its_main_choice(self):
        code, doc, _ = self.run_builder(surface(setter("key_name", "keyName"), setter("set_key_name", "keyName")), {
            "raw.rs": frame() + required("key_name")
                      + fragment("set_key_name", "a string", ".set_key_name(Some(\"x\".into()))", "alt"),
        })
        self.assertEqual(code, 0, doc["uncovered"])
        [choice] = doc["apis"][0]["choices"]
        self.assertEqual([a["setter"] for a in choice["alts"]], ["    .set_key_name(Some(\"x\".into()))"])

    def test_alt_without_a_main_choice_fails(self):
        code, doc, _ = self.run_builder(surface(setter("key_name", "keyName"), setter("set_key_name", "keyName")), {
            "raw.rs": required("key_name")
                      + fragment("set_key_name", "a map", ".set_key_name(None)", "alt"),
        })
        self.assertEqual(code, 1)
        self.assertIn((API, "set_key_name", "an alt with have='a map', which no main choice has"), whys(doc))

    def test_way_without_a_working_fragment_and_api_without_frame_fail(self):
        code, doc, out = self.run_builder(surface(setter("key_name", "keyName")), {
            "raw.rs": fragment("key_name", "an empty string", ".key_name(\"\")", "fails=validation")
                      + left_out("key_name"),
        })
        self.assertEqual(code, 1)
        self.assertEqual(whys(doc), {(API, None, "no frame"), (API, "builder", "no frame or example"),
                                     (API, "key_name", "no fragment that works")})
        self.assertIn(f"{API} key_name: no fragment that works", out)

    def test_overload_without_matching_takes_fails(self):
        way = setter("wrappingKey", "wrappingKey", overloads=["byte[]", "SecretKey"])
        code, doc, _ = self.run_builder(surface(way), {
            "Raw.java": frame() + fragment("wrappingKey", "bytes in memory", ".wrappingKey(bytes)",
                                           "takes=byte[] default")
                        + left_out("wrappingKey", "fails=validation"),
        })
        self.assertEqual(code, 1)
        self.assertEqual(whys(doc), {(API, "wrappingKey", "no fragment with takes=SecretKey")})

    def test_option_without_left_out_block_fails(self):
        code, doc, _ = self.run_builder(surface(setter("key_name", "keyName")), {
            "raw.rs": frame() + fragment("key_name", "a string", ".key_name(\"x\")"),
        })
        self.assertEqual(code, 1)
        self.assertEqual(whys(doc), {(API, "key_name", "no left-out block, so required is unknown")})

    def test_left_out_that_fails_and_one_that_works_fails(self):
        code, doc, _ = self.run_builder(surface(setter("key_name", "keyName"), setter("set_key_name", "keyName")), {
            "raw.rs": frame() + required("key_name") + left_out("set_key_name"),
        })
        self.assertEqual(code, 1)
        self.assertIn((API, "key_name", "a left-out block that fails and one that works, so required is unclear"),
                      whys(doc))

    def test_optional_option_needs_no_default_and_required_one_does(self):
        code, doc, _ = self.run_builder(surface(setter("key_name", "keyName"), setter("ttl", "ttl")), {
            "raw.rs": frame() + optional("ttl")
                      + fragment("key_name", "a string", ".key_name(\"x\")")
                      + left_out("key_name", "fails=validation"),
        })
        self.assertEqual(code, 1)
        self.assertEqual(whys(doc), {(API, "key_name", "a required option needs a default choice")})
        self.assertEqual([w.get("required") for w in doc["apis"][0]["ways"]], [None, True, False])

    def test_one_of_group_needs_left_out_and_together_blocks(self):
        ways = (setter("keyring", "keyring"), setter("cmm", "cmm"))
        code, doc, _ = self.run_builder(surface(*ways), {
            "e.rs": frame("one-of=keyring,cmm")
                    + fragment("keyring", "a keyring", ".keyring(k)", "default") + left_out("keyring")
                    + fragment("cmm", "a CMM", ".cmm(c)") + left_out("cmm"),
        })
        self.assertEqual(code, 1)
        self.assertEqual(whys(doc), {(API, "keyring,cmm", "a one-of group needs a left-out block that fails"),
                                     (API, "keyring,cmm", "a one-of group needs a together block")})
        code, doc, _ = self.run_builder(surface(*ways), {
            "e.rs": frame("one-of=keyring,cmm")
                    + fragment("keyring", "a keyring", ".keyring(k)", "default") + left_out("keyring")
                    + fragment("cmm", "a CMM", ".cmm(c)") + left_out("cmm")
                    + left_out("keyring,cmm", "fails=validation") + together("keyring,cmm", "validation"),
        })
        self.assertEqual(code, 0, doc["uncovered"])
        self.assertEqual(doc["apis"][0]["frame"]["one_of"], ["extra:keyring", "extra:cmm"])

    def test_marker_for_unknown_way_fails_with_its_place(self):
        code, doc, _ = self.run_builder({"schema": 1, "language": "rust", "library": "mpl", "apis": []}, {
            "old.rs": "\n" + fragment("gone", "a string", ".gone(1)"),
        })
        self.assertEqual(code, 1)
        [failure] = doc["uncovered"]
        self.assertEqual((failure["api"], failure["way"], failure["file"], failure["line"]),
                         (API, "gone", "tests/old.rs", 2))

    def test_malformed_markers_fail(self):
        code, doc, _ = self.run_builder({"schema": 1, "language": "rust", "library": "mpl", "apis": []}, {
            "a.rs": f"// api-example: api={API} way=x have=a\nlet a = 1;\n",
            "b.rs": f"// api-example: api={API} way=x have=\"a string\n// api-example: end\n",
            "c.rs": f"// api-example: api={API} way=x\n// api-example: setter\n.x(1)\n// api-example: end\n",
            "d.rs": f"// api-example: api={API} way=x kind=pass have=a\n// api-example: end\n",
            "e.rs": f"// api-example: api={API} frame way=x\n// api-example: setter\n.x(1)\n// api-example: end\n",
            "f.rs": f"// api-example: api={API} way=x have=a\n// api-example: setter\n// api-example: end\n",
            "g.rs": "// api-example: end\n",
        })
        self.assertEqual(code, 1)
        self.assertEqual(sorted((f["file"], f["why"]) for f in doc["uncovered"]), [
            ("tests/a.rs", "no // api-example: end before the next marker or end of file"),
            ("tests/b.rs", "a quote is not closed"),
            ("tests/c.rs", "a fragment needs have="),
            ("tests/d.rs", "unknown or repeated fields: kind=pass"),
            ("tests/e.rs", "a frame has no setter line"),
            ("tests/f.rs", "no setter line after // api-example: setter"),
            ("tests/g.rs", "a // api-example: tag outside a block"),
        ])

    def test_template_and_combo_results_go_into_the_output(self):
        (self.root / "combos.template").write_text(
            "notes\n@@ new-test\nfn {{name}}() {\n    {{code}}\n}\n@@ todo\ntodo!()\n@@ ok\nresult.unwrap();\n")
        (self.root / "combos.json").write_text(json.dumps({"schema": 1, "apis": [{
            "api": API, "mode": "all", "total": 2, "combos": [
                {"name": "a_001", "choices": {"keyName": "a string"}, "expect": "ok", "error": None, "outcome": "pass"},
                {"name": "a_002", "choices": {"keyName": None}, "expect": "fails", "error": "validation",
                 "outcome": "pass"},
                {"name": "a_003", "choices": {"keyName": None}, "expect": "ok", "error": None, "outcome": None}]}]}))
        code, doc, out = self.run_builder(surface(setter("key_name", "keyName")), {"raw.rs": frame() + required("key_name")},
                                          extra=["--template", "combos.template", "--combos", "combos.json"])
        self.assertEqual(code, 0, doc["uncovered"])
        self.assertEqual(doc["templates"], {"new-test": "fn {{name}}() {\n    {{code}}\n}", "todo": "todo!()"})
        combos = doc["apis"][0]["combos"]
        self.assertEqual((combos["mode"], combos["total"]), ("all", 2))
        self.assertEqual([(r["name"], r["choices"]) for r in combos["results"]],
                         [("a_001", {"extra:keyName": "a string"}), ("a_002", {"extra:keyName": None})])
        self.assertIn("2 calls built and run", out)


def names_entry(members=(), operations=(), aliases=None):
    return {"shape": "ns#Input", "members": list(members), "operations": list(operations),
            "aliases": aliases or {}}


class RowTest(TempDirTest):

    def rows(self, doc):
        return [(r["key"], r["kind"]) for r in doc["apis"][0]["rows"]]

    def way_rows(self, doc):
        return {w["id"]: w["row"] for w in doc["apis"][0]["ways"]}

    def test_rust_setter_pair_lands_on_the_smithy_member_row(self):
        code, doc, _ = self.run_builder(
            surface(setter("key_name", "keyName"), setter("set_key_name", "keyName")),
            {"raw.rs": frame() + required("key_name")
                       + fragment("set_key_name", "a string", ".set_key_name(Some(x))", "alt")},
            {API: names_entry(["keyName"])})
        self.assertEqual(code, 0, doc["uncovered"])
        self.assertEqual(self.way_rows(doc), {"builder": "construct", "key_name": "keyName", "set_key_name": "keyName"})

    def test_option_matches_member_that_differs_only_in_underscores(self):
        code, doc, _ = self.run_builder(
            surface(setter("set_net_v4_0_0_retry_policy", "netV400RetryPolicy")),
            {"raw.rs": frame() + optional("set_net_v4_0_0_retry_policy")},
            {API: names_entry(["netV4_0_0_RetryPolicy"])})
        self.assertEqual(code, 0, doc["uncovered"])
        self.assertEqual(self.way_rows(doc)["set_net_v4_0_0_retry_policy"], "netV4_0_0_RetryPolicy")

    def test_alias_maps_a_renamed_option_to_its_member(self):
        code, doc, _ = self.run_builder(surface(setter("ttl", "ttl")), {"raw.rs": frame() + optional("ttl")},
                                        {API: names_entry(["ttlSeconds"], aliases={"ttl": "ttlSeconds"})})
        self.assertEqual(self.way_rows(doc)["ttl"], "ttlSeconds")
        self.assertEqual(self.rows(doc), [("construct", "construct"), ("ttlSeconds", "member")])

    def test_method_lands_on_its_operation_row_and_api_has_no_construct_row(self):
        encrypt = {"id": "encrypt", "option": None, "kind": "method", "signature": "..."}
        s = surface(setter("plaintext", "plaintext"))
        s["apis"][0]["ways"] = [encrypt, setter("plaintext", "plaintext")]
        code, doc, _ = self.run_builder(s, {
            "e.rs": frame().replace("way=builder", "way=encrypt") + required("plaintext"),
        }, {API: names_entry(["plaintext", "keyring"], ["Encrypt"])})
        self.assertEqual(code, 0, doc["uncovered"])
        self.assertEqual(self.way_rows(doc), {"encrypt": "Encrypt", "plaintext": "plaintext"})
        self.assertEqual(self.rows(doc), [("Encrypt", "operation"), ("plaintext", "member"), ("keyring", "member")])

    def test_rows_follow_model_order_and_list_haves_in_source_order(self):
        code, doc, _ = self.run_builder(
            surface(setter("key_name", "keyName")), {
                "raw.rs": frame() + fragment("key_name", "a string from your config", ".key_name(k)")
                          + fragment("key_name", "a string", ".key_name(\"x\")", "default")
                          + left_out("key_name", "fails=validation"),
            }, {API: names_entry(["keyNamespace", "keyName"])})
        self.assertEqual(code, 0, doc["uncovered"])
        self.assertEqual({r["key"]: r["haves"] for r in doc["apis"][0]["rows"]}, {
            "construct": [], "keyNamespace": [], "keyName": ["a string from your config", "a string"]})

    def test_option_not_in_the_model_is_an_extra_row_and_does_not_fail(self):
        code, doc, _ = self.run_builder(surface(setter("grant_tokens", "grantTokens")),
                                        {"raw.rs": frame() + optional("grant_tokens")},
                                        {API: names_entry(["kmsKeyId"])})
        self.assertEqual(code, 0, doc["uncovered"])
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


if __name__ == "__main__":
    unittest.main()


PHRASES = json.loads(builder.Path(builder.__file__).with_name("type-phrases.json").read_text())["phrases"]


def take(t, sig):
    return {"type": t, "signature": sig}


class ShippedTest(unittest.TestCase):
    NAMES = {API: {"members": ["keyNamespace", "keyName", "wrappingKey", "wrappingAlg"], "operations": [], "aliases": {}}}

    def doc(self, *ways):
        s = {"schema": 1, "language": "java", "library": "mpl", "shipped": {"package": "p", "version": "1.11.1"},
             "apis": [{"id": API, "group": "Keyrings", "name": "Raw AES keyring", "type": "T",
                       "ways": [{"id": "CreateRawAesKeyring", "option": None, "kind": "constructor",
                                 "signature": "materialProviders.CreateRawAesKeyring(CreateRawAesKeyringInput)"}, *ways]}]}
        return builder.build_shipped(s, self.NAMES, PHRASES, "aws/aws-crypto-tools-commons", "abc", {"id": 1, "attempt": 1})

    def test_each_type_becomes_a_shipped_choice_named_by_the_phrase_table(self):
        doc = self.doc({"id": "wrappingKey", "option": "wrappingKey", "kind": "setter", "signature": "...",
                        "takes": [take("java.nio.ByteBuffer", "wrappingKey(ByteBuffer)"), take("byte[]", "wrappingKey(byte[])")]},
                       {"id": "keyName", "option": "keyName", "kind": "setter", "signature": "...",
                        "takes": [take("java.lang.String", "keyName(String)"), take("*string", "KeyName: string")]})
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
        doc = self.doc({"id": "wrappingAlg", "option": "wrappingAlg", "kind": "setter", "signature": "...",
                        "takes": [take("software.amazon.cryptography.materialproviders.model.AesWrappingAlg", "wrappingAlg(AesWrappingAlg)")]})
        self.assertEqual(doc["apis"][0]["choices"][0]["have"], "AesWrappingAlg")

    def test_the_phrase_table_names_the_usual_types(self):
        self.assertEqual({t: builder.have_of(t, PHRASES) for t in
                          ["byte[]", "bytes", "[]byte", "Uint8Array", "java.nio.ByteBuffer", "System.IO.MemoryStream",
                           "java.io.InputStream", "NodeJS.ReadableStream", "str", "String", "java.util.Map<java.lang.String, java.lang.String>",
                           "dict", "Int64?", "*int64"]}, {
            "byte[]": "bytes in memory", "bytes": "bytes in memory", "[]byte": "bytes in memory", "Uint8Array": "bytes in memory",
            "java.nio.ByteBuffer": "a byte buffer", "System.IO.MemoryStream": "a memory stream",
            "java.io.InputStream": "a stream", "NodeJS.ReadableStream": "a stream", "str": "a string", "String": "a string",
            "java.util.Map<java.lang.String, java.lang.String>": "a map", "dict": "a map", "Int64?": "a number", "*int64": "a number"})

    def test_no_type_is_in_the_phrase_table_twice(self):
        types = [t for ts in PHRASES.values() for t in ts]
        self.assertEqual(sorted({t for t in types if types.count(t) > 1}), [])
