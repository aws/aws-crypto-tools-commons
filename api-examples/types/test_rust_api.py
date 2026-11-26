import unittest

import rust_api


def span(file, begin, end):
    return {"filename": file, "begin": [begin, 1], "end": [end, 2]}


# A rustdoc index with one builder struct, an inherent impl and a Default impl.
DOC = {"index": {
    "1": {"crate_id": 0, "name": "RawAesKeyringBuilder", "span": span("src/keyring/raw_aes_keyring.rs", 226, 231),
          "inner": {"struct": {"impls": [2, 3]}}},
    "2": {"crate_id": 0, "name": None, "inner": {"impl": {"trait": None, "items": [4, 5]}}},
    "3": {"crate_id": 0, "name": None, "inner": {"impl": {"trait": {"path": "Default"}, "items": [6]}}},
    "4": {"crate_id": 0, "name": "wrapping_key", "span": span("src/keyring/raw_aes_keyring.rs", 302, 305),
          "inner": {"function": {}}},
    "5": {"crate_id": 0, "name": "set_wrapping_key", "span": span("mpl/src/keyring/raw_aes_keyring.rs", 310, 313),
          "inner": {"function": {}}},
    "6": {"crate_id": 0, "name": "default", "span": span("src/keyring/raw_aes_keyring.rs", 400, 402),
          "inner": {"function": {}}},
    # Another crate's type is not read.
    "7": {"crate_id": 3, "name": "Client", "span": span("src/client.rs", 1, 9), "inner": {"struct": {"impls": []}}},
}}


class MethodSpans(unittest.TestCase):
    def setUp(self):
        self.spans = rust_api.method_spans(DOC, "mpl")

    def test_each_method_of_the_types_own_impl_has_its_lines_from_the_repo_root(self):
        self.assertEqual(self.spans[("RawAesKeyringBuilder", "wrapping_key")],
                         {"file": "mpl/src/keyring/raw_aes_keyring.rs", "line": 302, "end": 305})

    def test_a_path_that_already_starts_at_the_repo_root_is_kept(self):
        self.assertEqual(self.spans[("RawAesKeyringBuilder", "set_wrapping_key")]["file"],
                         "mpl/src/keyring/raw_aes_keyring.rs")

    def test_the_type_itself_is_under_no_method(self):
        self.assertEqual(self.spans[("RawAesKeyringBuilder", None)]["line"], 226)

    def test_trait_impl_methods_and_other_crates_are_left_out(self):
        self.assertNotIn(("RawAesKeyringBuilder", "default"), self.spans)
        self.assertNotIn(("Client", None), self.spans)

    def test_an_option_gets_its_setters_lines_and_its_set_setters_lines(self):
        options = [{"name": "wrapping_key", "setter": "wrapping_key", "set": "set_wrapping_key", "ctor": None},
                   {"name": "keyring", "setter": None, "set": None, "ctor": "new"}]
        spans = {**self.spans, ("DefaultCmm", "new"): {"file": "mpl/src/cmm.rs", "line": 40, "end": 44}}
        rust_api.add_spans(options[:1], "RawAesKeyringBuilder", spans)
        rust_api.add_spans(options[1:], "DefaultCmm", spans)
        self.assertEqual(options[0]["span"]["line"], 302)
        self.assertEqual(options[0]["set_span"]["line"], 310)
        self.assertEqual(options[1]["span"]["line"], 40)
        self.assertNotIn("set_span", options[1])


if __name__ == "__main__":
    unittest.main()
