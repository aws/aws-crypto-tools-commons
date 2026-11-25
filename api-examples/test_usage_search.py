"""Run with: python3 -m unittest discover -s api-examples"""

import json
import unittest
from pathlib import Path

import usage_search as us

NAMES = json.loads((Path(__file__).parent / "smithy-names.json").read_text())
SITES = us.smithy_sites(NAMES) + us.HAND_WRITTEN


def found(code, lang):
    """[(api, option, argument)] at every site in code."""
    return [(s.api, member, arg) for s in SITES if s.lang == lang for member, arg, _ in us.args(code, s, lang)]


class ArgsTest(unittest.TestCase):

    def test_java_builder_skips_comments_and_nested_calls(self):
        code = """
            CreateRawAesKeyringInput.builder()
                // the key name
                .keyName(names.get("a, b"))
                .wrappingKey(ByteBuffer.wrap(key))
                .build();
        """
        self.assertEqual(found(code, "java"), [
            ("raw-aes-keyring", "keyName", 'names.get("a, b")'),
            ("raw-aes-keyring", "wrappingKey", "ByteBuffer.wrap(key)")])

    def test_java_positional_encrypt_data(self):
        code = 'crypto.encryptData(keyring, text.getBytes(UTF_8), Collections.singletonMap("k", "v"))'
        self.assertEqual(found(code, "java"), [
            ("encrypt", "plaintext", "text.getBytes(UTF_8)"),
            ("encrypt", "encryptionContext", 'Collections.singletonMap("k", "v")')])

    def test_rust_operation_chain_with_await(self):
        code = """
            let k = mpl.create_aws_kms_keyring()
                .kms_key_id(arn.to_string())
                .kms_client(client.clone())
                .send()
                .await?;
            let ct = esdk.encrypt().plaintext(b"hi".to_vec()).keyring(k).send().await?;
        """
        self.assertEqual(found(code, "rust"), [
            ("encrypt", "plaintext", 'b"hi".to_vec()'),
            ("encrypt", "keyring", "k"),
            ("aws-kms-keyring", "kmsKeyId", "arn.to_string()"),
            ("aws-kms-keyring", "kmsClient", "client.clone()")])

    def test_rust_lifetime_is_not_a_string(self):
        code = "fn f<'a>(x: &'a [u8]) { CreateRawAesKeyringInput::builder().key_name(n) }"
        self.assertEqual(found(code, "rust"), [("raw-aes-keyring", "keyName", "n")])

    def test_python_keywords_skip_comparisons_and_comments(self):
        code = """client.encrypt(
            source=text.encode("utf-8"),  # source=ignored
            keyring=k if a == b else k2,
        )"""
        self.assertEqual(found(code, "python"), [
            ("encrypt", "plaintext", 'text.encode("utf-8")'),
            ("encrypt", "keyring", "k if a == b else k2")])

    def test_python_master_key_provider_counts_as_multi_keyring(self):
        code = "StrictAwsKmsMasterKeyProvider(key_ids=[os.environ['KEY']])"
        self.assertEqual(found(code, "python"), [("aws-kms-multi-keyring", "kmsKeyIds", "[os.environ['KEY']]")])

    def test_dotnet_object_initializer(self):
        code = "var input = new EncryptInput { Plaintext = new MemoryStream(bytes), Keyring = keyring };"
        self.assertEqual(found(code, "dotnet"), [
            ("encrypt", "plaintext", "new MemoryStream(bytes)"), ("encrypt", "keyring", "keyring")])

    def test_go_struct_literal(self):
        code = "in := esdktypes.EncryptInput{Plaintext: []byte(text), Keyring: k}"
        self.assertEqual(found(code, "go"), [
            ("encrypt", "plaintext", "[]byte(text)"), ("encrypt", "keyring", "k")])

    def test_js_positional_with_options_object_and_shorthand_fields(self):
        code = """
            const keyring = new KmsKeyringNode({ generatorKeyId, keyIds: [other] })
            const { result } = await encrypt(keyring, Buffer.from(text), { encryptionContext: context })
        """
        self.assertEqual(found(code, "javascript"), [
            ("encrypt", "plaintext", "Buffer.from(text)"),
            ("encrypt", "encryptionContext", "context"),
            ("aws-kms-multi-keyring", "generator", "generatorKeyId"),
            ("aws-kms-multi-keyring", "kmsKeyIds", "[other]")])

    def test_js_call_with_too_few_args_is_not_a_hit(self):
        self.assertEqual(found("kms.decrypt(params)", "javascript"), [])


# One argument per rule that only that rule classifies. A rule with no sample fails test_every_rule_has_a_sample.
SAMPLES = {
    ".getBytes(...)": ("java", "s.getBytes(StandardCharsets.UTF_8)"),
    ".encode()": ("python", "s.encode()"),
    "bytes(..., encoding)": ("python", 'bytes(s, "utf-8")'),
    "b\"...\" literal": ("python", 'b"secret"'),
    "Buffer.from(...)": ("javascript", "Buffer.from(s)"),
    "TextEncoder.encode": ("javascript", "new TextEncoder().encode(s)"),
    ".as_bytes()": ("rust", "s.as_bytes()"),
    ".into_bytes()": ("rust", "s.into_bytes()"),
    "[]byte(...)": ("go", "[]byte(s)"),
    "Encoding.UTF8.GetBytes": ("dotnet", "Encoding.UTF8.GetBytes(s)"),
    "string literal": ("java", '"arn:aws:kms:us-west-2:111122223333:key/k"'),
    "Files.readAllBytes": ("java", "Files.readAllBytes(path)"),
    ".read()": ("python", "f.read()"),
    "fs.readFileSync": ("javascript", "fs.readFileSync(path)"),
    "fs::read": ("rust", "std::fs::read(path)"),
    "File.ReadAllBytes": ("dotnet", "File.ReadAllBytes(path)"),
    "os.ReadFile": ("go", "os.ReadFile(path)"),
    "base64 decode": ("python", "base64.b64decode(s)"),
    "hex decode": ("python", "bytes.fromhex(s)"),
    "environment variable": ("javascript", "process.env.KEY_ARN"),
    "ByteBuffer.wrap": ("java", "ByteBuffer.wrap(key)"),
    "new MemoryStream(...)": ("dotnet", "new MemoryStream(key)"),
    ".to_vec()": ("rust", "key.to_vec()"),
    "Some(x.into())": ("rust", "Some(x.into())"),
    ".to_string()": ("rust", "arn.to_string()"),
    "str(...)": ("python", "str(key_id)"),
    ".toString()": ("java", "id.toString()"),
    "list literal": ("python", "[arn]"),
    "list of one": ("java", "List.of(arn)"),
    "map literal": ("java", 'Map.of("k", "v")'),
}


def labels(arg, lang, before=()):
    return [r if r == us.AS_IS else r.label for r in us.classify(arg, list(before), lang)]


class ClassifyTest(unittest.TestCase):

    def test_every_rule_has_a_sample(self):
        self.assertEqual(sorted(SAMPLES), sorted(r.label for r in us.RULES))

    def test_each_sample_matches_only_its_rule(self):
        for label, (lang, arg) in SAMPLES.items():
            with self.subTest(label):
                self.assertEqual(labels(arg, lang), [label])

    def test_rules_apply_only_to_their_language(self):
        self.assertEqual(labels("s.getBytes(UTF_8)", "python"), [us.AS_IS])

    def test_base64_buffer_is_not_a_string(self):
        self.assertEqual(labels("Buffer.from(s, 'base64')", "javascript"), ["base64 decode"])

    def test_nested_conversions_count_each(self):
        self.assertEqual(labels("ByteBuffer.wrap(s.getBytes(UTF_8))", "java"), [".getBytes(...)", "ByteBuffer.wrap"])

    def test_variable_takes_the_conversion_on_the_line_that_assigns_it(self):
        before = ["plaintext = other.encode()", "x = 1", "plaintext = data.encode('utf-8')", "y = plaintext == z"]
        self.assertEqual(labels("plaintext", "python", before), [".encode()"])

    def test_go_short_assignment_and_rust_borrow(self):
        self.assertEqual(labels("pt", "go", ["pt := []byte(text)"]), ["[]byte(...)"])
        self.assertEqual(labels("&key", "rust", ["let key = fs::read(path)?;"]), ["fs::read"])

    def test_unconverted_argument_is_passed_as_is(self):
        self.assertEqual(labels("plaintext", "python", ["def f(plaintext):"]), [us.AS_IS])


class CallsTest(unittest.TestCase):

    def test_file_without_the_import_has_no_calls(self):
        code = "client.encrypt(source=text.encode())"
        self.assertEqual(us.calls(code, "python", SITES), [])
        hits = us.calls("import aws_encryption_sdk\n" + code, "python", SITES)
        self.assertEqual([(h[1], h[2], h[3].label, h[4]) for h in hits], [("encrypt", "plaintext", ".encode()", 2)])

    def test_customer_filter(self):
        def item(owner="acme", fork=False, private=False, path="src/app.py"):
            return {"path": path, "repository": {"owner": {"login": owner}, "fork": fork, "private": private}}
        self.assertTrue(us.is_customer(item()))
        for bad in (item(owner="awslabs"), item(owner="AWS"), item(fork=True), item(private=True),
                    item(path="web/node_modules/x/index.js"),
                    item(path="src/main/java/com/amazonaws/encryptionsdk/AwsCrypto.java")):
            self.assertFalse(us.is_customer(bad), bad)

    def test_add_ranks_and_keeps_one_example_per_repo(self):
        apis = {}
        rule = next(r for r in us.RULES if r.label == ".encode()")
        for repo in ("a/x", "a/x", "b/y"):
            us.add(apis, "python", repo, "app.py", "c0ffee", ("esdk", "encrypt", "plaintext", rule, 3))
        us.add(apis, "python", "c/z", "app.py", "c0ffee", ("esdk", "encrypt", "plaintext", us.AS_IS, 9))
        out = us.ranked(apis)["esdk|encrypt"]["plaintext"]
        self.assertEqual([(c["conversion"], c["count"], c["from"]) for c in out],
                         [(".encode()", 3, "a string"), (us.AS_IS, 1, None)])
        self.assertEqual([e["repo"] for e in out[0]["examples"]], ["a/x", "b/y"])
        self.assertEqual(out[0]["examples"][0]["url"], "https://github.com/a/x/blob/c0ffee/app.py#L3")

    def test_each_call_keeps_its_line_and_the_assignment_that_converted_it(self):
        code = "import aws_encryption_sdk\npt = text.encode()\nclient.encrypt(source=pt)"
        hits = us.calls(code, "python", SITES)
        self.assertEqual([(h[4], h[5], h[6]) for h in hits], [(3, "client.encrypt(source=pt)", "pt = text.encode()")])

    def test_the_assignment_is_kept_only_when_it_did_the_conversion(self):
        def found(arg, before):
            hits, assignment = us.classify_with_source(arg, before, "python")
            return [h if h == us.AS_IS else h.label for h in hits], assignment
        self.assertEqual(found("pt", ["pt = text.encode()"]), ([".encode()"], "pt = text.encode()"))
        self.assertEqual(found("text.encode()", ["pt = other.encode()"]), ([".encode()"], None))
        self.assertEqual(found("pt", ["pt = load()"]), ([us.AS_IS], None))

    def test_copies_of_aws_code_are_listed_but_not_counted(self):
        apis = {}
        rule = next(r for r in us.RULES if r.label == ".encode()")
        hit = ("esdk", "encrypt", "plaintext", rule, 3, "client.encrypt(source=s.encode())", None)
        us.add(apis, "python", "a/x", "app.py", "c0ffee", hit, "b1")
        us.add(apis, "python", "b/y", "lambda/aws_lambda_powertools/utilities/kms.py", "c0ffee", hit, "b2")
        c = us.ranked(apis)["esdk|encrypt"]["plaintext"][0]
        self.assertEqual((c["count"], c["languages"], c["repos"], c["sources"], c["aws_copies"]),
                         (1, {"python": 1}, 1, 1, 1))
        self.assertEqual([(h["repo"], h["aws_copy"]) for h in c["hits"]], [("a/x", False), ("b/y", True)])
        self.assertEqual([e["repo"] for e in c["examples"]], ["a/x"])

    def test_aws_code_copies_are_folders_named_after_aws_code(self):
        for path in ("aws_lambda_powertools/utilities/kms.py", "deps/aws-encryption-sdk-python/src/basic.py",
                     "x/aws-cryptographic-material-providers-library/src/keyring.py"):
            self.assertTrue(us.AWS_CODE_COPY.search(path), path)
        for path in ("app/aws_encryption.py", "src/aws-encryption-sdk.py", "my-aws-encryption-sdk-app/main.py"):
            self.assertFalse(us.AWS_CODE_COPY.search(path), path)


class GroupCopiesTest(unittest.TestCase):

    def test_hits_in_one_file_or_in_copies_of_a_file_share_a_source(self):
        def hit(repo, path, code, blob=None):
            return {"repo": repo, "path": path, "code": code, "blob": blob}
        hits = [hit("a/x", "app/main.py", "one"), hit("a/x", "app/main.py", "two"),  # one file
                hit("b/y", "other.py", "one", "f00d"), hit("c/z", "renamed.py", "two", "f00d"),  # same content
                hit("d/w", "src/pkg/crypto.py", "same"), hit("e/v", "lib/src/pkg/crypto.py", "same"),  # same tail and line
                hit("f/u", "lib/src/pkg/crypto.py", "other"),  # same tail, another line
                hit("g/t", "pkg/crypto.py", "same")]  # a tail shorter than TAIL parts
        self.assertEqual(us.group_copies(hits), 5)
        self.assertEqual([h["source"] for h in hits], [0, 0, 1, 1, 2, 2, 3, 4])

    def test_a_hit_that_links_two_sources_joins_them(self):
        # The last hit is in the second hit's file, and has the first hit's line in a copy of its file.
        hits = [{"repo": "a/x", "path": "one/src/pkg/crypto.py", "code": "first", "blob": None},
                {"repo": "b/y", "path": "two/src/pkg/crypto.py", "code": "second", "blob": None},
                {"repo": "b/y", "path": "two/src/pkg/crypto.py", "code": "first", "blob": None}]
        self.assertEqual(us.group_copies(hits), 1)
        self.assertEqual({h["source"] for h in hits}, {0})


if __name__ == "__main__":
    unittest.main()
