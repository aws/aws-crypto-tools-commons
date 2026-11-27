"""Run with: python3 -m unittest discover -s api-examples"""

import unittest

import read_shipped as r

# Trimmed javap -l output of the Java ESDK 3.0.2. The access$500 method is
# package-private, so its local variable must not land on encryptData.
JAVAP = """\
public class com.amazonaws.encryptionsdk.AwsCrypto {
  public com.amazonaws.encryptionsdk.CryptoResult<byte[], ?> encryptData(software.amazon.cryptography.materialproviders.IKeyring, byte[], java.util.Map<java.lang.String, java.lang.String>);
    LineNumberTable:
      line 440: 0
    LocalVariableTable:
      Start  Length  Slot  Name   Signature
          0      19     0  this   Lcom/amazonaws/encryptionsdk/AwsCrypto;
          0      19     2 plaintext   [B
          0      19     1 keyring   Lsoftware/amazon/cryptography/materialproviders/IKeyring;
          0      19     3 encryptionContext   Ljava/util/Map;
          7      12     4 result   Lcom/amazonaws/encryptionsdk/CryptoResult;

  static com.amazonaws.encryptionsdk.CryptoAlgorithm access$500(com.amazonaws.encryptionsdk.AwsCrypto);
    LocalVariableTable:
      Start  Length  Slot  Name   Signature
          0       5     0    x0   Lcom/amazonaws/encryptionsdk/AwsCrypto;
}
public interface software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput$Builder {
  public abstract software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput$Builder wrappingKey(java.nio.ByteBuffer);
}
"""


class JavapTest(unittest.TestCase):
    def test_parameter_names_come_from_the_local_variable_table_in_slot_order(self):
        classes = r.parse_javap(JAVAP)
        [m] = classes["com.amazonaws.encryptionsdk.AwsCrypto"]
        self.assertEqual(m["name"], "encryptData")
        self.assertEqual([(p["name"], p["type"]) for p in m["params"]], [
            ("keyring", "software.amazon.cryptography.materialproviders.IKeyring"),
            ("plaintext", "byte[]"),
            ("encryptionContext", "java.util.Map<java.lang.String, java.lang.String>"),
        ])
        self.assertEqual(r.java_call(m), "encryptData(IKeyring keyring, byte[] plaintext, Map<String, String> encryptionContext)")

    def test_an_interface_method_has_no_parameter_names(self):
        [m] = r.parse_javap(JAVAP)["software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput$Builder"]
        self.assertEqual(m["params"], [{"type": "java.nio.ByteBuffer", "name": None}])
        self.assertEqual(r.java_call(m), "wrappingKey(ByteBuffer)")


class PythonTest(unittest.TestCase):
    def test_type_hints_open_up_optional_and_unions(self):
        self.assertEqual(r.py_types("Optional[list[str]]"), ["list[str]"])
        self.assertEqual(r.py_types("Union[bytes, bytearray]"), ["bytes", "bytearray"])
        self.assertEqual(r.py_types("bytes | bytearray | None"), ["bytes", "bytearray"])
        self.assertEqual(r.py_types("'Keyring'"), ["Keyring"])

    def test_docstring_types_come_from_param_and_type_lines(self):
        doc = """Encrypts.

        :param source: Source data to encrypt or decrypt
        :type source: str, bytes, io.IOBase, or file
        :param dict encryption_context: Dictionary defining encryption context
        :param max_encrypted_data_keys: The maximum number
        :type max_encrypted_data_keys: None or positive int
        """
        self.assertEqual(r.doc_types(doc), {
            "source": ["str", "bytes", "io.IOBase", "file"],
            "encryption_context": ["dict"],
            "max_encrypted_data_keys": ["positive int"],
        })


class RenameTest(unittest.TestCase):
    def test_a_rename_can_depend_on_the_type(self):
        table = {"cmm": {"KeyringNode": "keyring", "NodeMaterialsManager": "materialsManager"}, "suiteId": "algorithmSuiteId"}
        self.assertEqual(r.renamed(table, "cmm", "KeyringNode"), "keyring")
        self.assertEqual(r.renamed(table, "cmm", "NodeMaterialsManager"), "materialsManager")
        self.assertEqual(r.renamed(table, "suiteId", "AlgorithmSuiteIdentifier"), "algorithmSuiteId")
        self.assertEqual(r.renamed(table, "frameLength", "number"), "frameLength")


if __name__ == "__main__":
    unittest.main()
