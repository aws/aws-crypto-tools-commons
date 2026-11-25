"""Tests for finding the names in a type that still need a path."""
import unittest

from compile_rust_types import bare_names


class BareNamesTest(unittest.TestCase):
    def test_names_with_a_path_are_left_alone(self):
        self.assertEqual(bare_names("Option<&Blob>"), ["Blob"])
        self.assertEqual(bare_names("std::sync::Arc<aws_sdk_kms::Client>"), [])
        self.assertEqual(bare_names("HashMap<String, String>"), ["HashMap"])


if __name__ == "__main__":
    unittest.main()
