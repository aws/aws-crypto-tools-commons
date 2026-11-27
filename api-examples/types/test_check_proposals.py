"""Tests for how check_proposals.py models proposed setters and other languages' proposals."""
import unittest

from check_proposals import fits, other_rows, setter_line


class SetterLineTest(unittest.TestCase):
    def test_named_lifetimes_become_the_fns_own(self):
        self.assertEqual(setter_line("plaintext", ["impl Into<Plaintext<'a>>"]),
                         "pub fn plaintext<'a>(x: impl Into<Plaintext<'a>>) {}")
        self.assertEqual(setter_line("key", ["&'static str"]), "pub fn key(x: &'static str) {}")

    def test_a_pair_takes_x_and_y(self):
        self.assertEqual(setter_line("entry", ["String", "String"]), "pub fn entry(x: String, y: String) {}")


class FitsTest(unittest.TestCase):
    def test_option_fixes_go_only_to_set_setters(self):
        self.assertTrue(fits("set_plaintext", ["Option<Plaintext>"], "set"))
        self.assertFalse(fits("plaintext", ["Plaintext"], "set"))
        self.assertFalse(fits("set_plaintext", ["Option<Plaintext>"], "base"))

    def test_pair_fixes_go_only_to_two_parameter_setters(self):
        self.assertTrue(fits("entry", ["String", "String"], "pair"))
        self.assertFalse(fits("entry", ["String"], "pair"))


def row(type_, calls, code, kind):
    return {"type": type_, "calls": calls, "code": code, "kind": kind}


class OtherRowsTest(unittest.TestCase):
    ROWS = [row("byte[]", 0, "crypto.encryptData(keyring, x)", "bytes"),
            row("String", 1, "crypto.encryptData(keyring, x.getBytes(UTF_8))", "text"),
            row("Path", 1, "crypto.encryptData(keyring, Files.readAllBytes(x))", "file / stream")]

    def test_listed_kinds_become_as_is_and_keep_todays_cost(self):
        rows = other_rows(self.ROWS, {"as_is": ["text", "file / stream"]})
        self.assertEqual(rows[1], {**row("String", 0, "crypto.encryptData(keyring, x)", "text"),
                                   "today": 1, "proposed": True})

    def test_paths_and_unlisted_kinds_stay(self):
        rows = other_rows(self.ROWS, {"as_is": ["file / stream"]})
        self.assertEqual(rows[1], {**self.ROWS[1], "today": 1, "proposed": False})
        self.assertEqual(rows[2]["calls"], 1)

    def test_rename_changes_the_field_only_for_its_kind(self):
        go = [row("[]byte", 0, "EncryptInput{Plaintext: x}", "bytes"),
              row("*bytes.Buffer", 1, "EncryptInput{Plaintext: x.Bytes()}", "bytes"),
              row("io.Reader", 3, "data, err := io.ReadAll(x)", "file / stream")]
        spec = {"as_is": ["bytes", "file / stream"], "rename": ["Plaintext:", "PlaintextReader:", "file / stream"]}
        rows = other_rows(go, spec)
        self.assertEqual(rows[1]["code"], "EncryptInput{Plaintext: x}")
        self.assertEqual(rows[2]["code"], "EncryptInput{PlaintextReader: x}")


if __name__ == "__main__":
    unittest.main()
