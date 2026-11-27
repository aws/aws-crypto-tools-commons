"""Tests for counting the calls in a fix."""
import unittest

from calls import count, level


class CountTest(unittest.TestCase):
    def test_borrows_some_and_literals_are_free(self):
        for code in ("x", "&x", "&x[..]", "Some(x)", "[x]", "x, y", "map[string]string{k: v}"):
            self.assertEqual(count(code), 0, code)

    def test_each_call_counts(self):
        self.assertEqual(count("x.as_bytes()"), 1)
        self.assertEqual(count("Some(x.to_vec())"), 1)
        self.assertEqual(count("x.try_into().unwrap()"), 2)
        self.assertEqual(count("std::time::Duration::from_secs(x.into())"), 2)
        self.assertEqual(count("aws_sdk_kms::Client::new(&x)"), 1)

    def test_new_await_casts_and_function_literals_count(self):
        self.assertEqual(count("new ByteArrayInputStream(x)"), 1)
        self.assertEqual(count("new MemoryStream(Encoding.UTF8.GetBytes(x))"), 2)
        self.assertEqual(count("new Dictionary<string, string> { [k] = v }"), 1)
        self.assertEqual(count("Buffer.concat(await x.toArray())"), 3)
        self.assertEqual(count("(long)x.TotalSeconds"), 1)
        self.assertEqual(count("() => x"), 1)

    def test_extra_lines_count(self):
        self.assertEqual(count("data, err := io.ReadAll(x)\nif err != nil { return err }\ndata"), 3)


class LevelTest(unittest.TestCase):
    def test_levels(self):
        self.assertEqual([level(n) for n in (None, 0, 1, 2, 5)],
                         ["no fix found", "as is", "one call", ">1 call", ">1 call"])


if __name__ == "__main__":
    unittest.main()
