"""Tests for the rules that decide what kind of value a Rust type holds."""
import unittest

from rust_types import Evidence, accepted_kind, classify


def evidence(impls=(), definers=None, aliases=None):
    return Evidence(set(impls), definers or {}, aliases or {})


class ClassifyTest(unittest.TestCase):
    def test_std_types(self):
        ev = evidence()
        self.assertEqual(classify("&[u8]", ev), "bytes")
        self.assertEqual(classify("Cow<str>", ev), "text")
        self.assertEqual(classify("PathBuf", ev), "path")
        self.assertEqual(classify("File", ev), "reader")
        self.assertEqual(classify("u32", ev), "number")
        self.assertEqual(classify("Duration", ev), "duration")
        self.assertEqual(classify("Option<&str>", ev), "optional text")
        self.assertEqual(classify("HashMap<String, String>", ev), "map")
        self.assertEqual(classify("Vec<(String, String)>", ev), "map")
        self.assertEqual(classify("(&str, &str)", ev), "pair")
        self.assertEqual(classify("&[String]", ev), "list")

    def test_skipped_types(self):
        ev = evidence()
        self.assertIsNone(classify("Vec<_>", ev))
        self.assertIsNone(classify("[u8; N]", ev))
        self.assertIsNone(classify("impl AsRef<[u8]>", ev))

    def test_third_party_bytes_needs_an_impl(self):
        self.assertIsNone(classify("Bytes", evidence()))
        ev = evidence({("bytes", "AsRef<[u8]>", "Bytes")}, {"Bytes": {"bytes"}})
        self.assertEqual(classify("Bytes", ev), "bytes")

    def test_name_counts_only_when_every_defining_crate_has_the_impl(self):
        ev = evidence({("ring", "AsRef<[u8]>", "Tag")}, {"Tag": {"ring", "aws_sdk_s3"}})
        self.assertIsNone(classify("Tag", ev))

    def test_alias_with_the_same_name_must_hold_the_same_kind(self):
        impls = {("bytes", "AsRef<[u8]>", "Bytes"), ("rustls", "AsRef<[u8]>", "Output")}
        definers = {"Bytes": {"bytes"}, "Output": {"rustls"}}
        aliases = {"Bytes": {"[u8; 16]"}, "Output": {"TypeErasedBox"}}
        ev = evidence(impls, definers, aliases)
        self.assertEqual(classify("Bytes", ev), "bytes")
        self.assertIsNone(classify("Output", ev))

    def test_wrapper_holds_what_it_derefs_to(self):
        ev = evidence({("zeroize", "Deref<Target = _>", "Zeroizing<_>")}, {"Zeroizing": {"zeroize"}})
        self.assertEqual(classify("Zeroizing<String>", ev), "text")
        self.assertEqual(classify("Zeroizing<Vec<u8>>", ev), "bytes")

    def test_made_from_bytes_without_a_bytes_view_is_a_stream(self):
        impls = {("aws_smithy_types", "From<Vec<u8>>", "ByteStream"),
                 ("aws_smithy_types", "From<Vec<u8>>", "Blob"), ("aws_smithy_types", "AsRef<[u8]>", "Blob")}
        ev = evidence(impls, {"ByteStream": {"aws_smithy_types"}, "Blob": {"aws_smithy_types"}})
        self.assertEqual(classify("ByteStream", ev), "stream")
        self.assertEqual(classify("Blob", ev), "bytes")


class AcceptedKindTest(unittest.TestCase):
    def test_impl_params(self):
        ev = evidence()
        self.assertEqual(accepted_kind("impl AsRef<[u8]>", ev), "bytes")
        self.assertEqual(accepted_kind("impl Into<String>", ev), "text")
        self.assertEqual(accepted_kind("impl AsRef<Path>", ev), "path")
        self.assertEqual(accepted_kind("impl Read + Write", ev), "reader")
        self.assertIsNone(accepted_kind("impl Fn(u8)", ev))


if __name__ == "__main__":
    unittest.main()
