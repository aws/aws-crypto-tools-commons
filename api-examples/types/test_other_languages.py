"""Tests for turning a released library's signature into a call with the argument filled in."""
import unittest

from other_languages import template


class TemplateTest(unittest.TestCase):
    def test_java_method_keeps_other_parameter_names(self):
        sig = "crypto.encryptData(IKeyring keyring, byte[] plaintext, Map<String, String> encryptionContext)"
        self.assertEqual(template("java", sig, "Map<String, String>"), "crypto.encryptData(keyring, plaintext, {x})")

    def test_java_builder(self):
        sig = "CreateRawAesKeyringInput.builder().wrappingKey(ByteBuffer)"
        self.assertEqual(template("java", sig, "ByteBuffer"), "CreateRawAesKeyringInput.builder().wrappingKey({x})")

    def test_javascript_encrypt_takes_the_keyring_first(self):
        self.assertEqual(template("javascript", "client.encrypt(plaintext: Buffer)", "Buffer"), "encrypt(keyring, {x})")
        self.assertEqual(template("javascript", "client.encrypt({ frameLength: number })", "number"),
                         "encrypt(keyring, plaintext, { frameLength: {x} })")

    def test_field_and_keyword_forms(self):
        self.assertEqual(template("dotnet", "new EncryptInput { Plaintext = MemoryStream }", "MemoryStream"),
                         "new EncryptInput { Plaintext = {x} }")
        self.assertEqual(template("go", "EncryptInput{Plaintext: []byte}", "[]byte"), "EncryptInput{Plaintext: {x}}")
        self.assertEqual(template("python", "client.encrypt(source=bytes)", "bytes"), "client.encrypt(source={x})")


if __name__ == "__main__":
    unittest.main()
