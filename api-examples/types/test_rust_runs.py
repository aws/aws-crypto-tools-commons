"""Tests for writing the Rust run tests and reading what they print."""
import unittest

import rust_runs

PLAINTEXT = "esdk/encrypt.plaintext"
RECEIVERS = {PLAINTEXT: ("aws_esdk::Client::default()", ".encrypt()"),
             "esdk/encrypt.encryption_context": ("aws_esdk::Client::default()", ".encrypt()")}


def made(label, values=None, expr=None):
    """(skip reason, lines) for holding the plaintext value as `label`."""
    out = []
    why = rust_runs.make("x", label, expr or label, values or rust_runs.OPTIONS[PLAINTEXT]["values"], out)
    return why, out


class MakeTest(unittest.TestCase):
    def test_a_borrow_holds_an_owned_value(self):
        self.assertEqual(made("&[u8]"), (None, ["let x_owned = plaintext_bytes();", "let x: &[u8] = &x_owned;"]))
        self.assertEqual(made("&str")[1], ["let x_owned = plaintext_text();", "let x: &str = &x_owned;"])

    def test_an_option_wraps_the_value(self):
        self.assertEqual(made("Option<String>"), (None, ["let x_inner = plaintext_text();", "let x = Some(x_inner);"]))

    def test_a_number_that_does_not_fit_skips(self):
        values = {"number": "FRAME_LENGTH"}
        self.assertEqual(made("u8", values)[1], ['let Ok(x) = u8::try_from(FRAME_LENGTH) else { '
                                                'r.skip("the value does not fit in a u8"); return; };'])
        self.assertIn('"the value does not fit in an i8"', made("i8", values)[1][0])

    def test_a_fixed_size_array_needs_that_many_bytes(self):
        self.assertEqual(made("[u8; 32]")[1][1], 'let Ok(x) = <[u8; 32]>::try_from(x_bytes.as_slice()) else { '
                                                 'r.skip("the value is not 32 bytes"); return; };')

    def test_types_it_cannot_hold_say_why(self):
        self.assertEqual(made("TcpStream"), ("needs a network connection", []))
        self.assertEqual(made("String", {"bytes": "key_bytes()"}), ("this option takes no text", []))
        self.assertEqual(made("Vec<u8>", {"text": "KEY_NAME.to_string()"}), ("this option takes no bytes", []))
        self.assertEqual(made("u32", {"text": "KEY_NAME.to_string()"}), ("this option takes no number", []))
        self.assertEqual(made("Rc<[u8]>"), ("no way to hold the value in this type yet", []))


def trial(label, glue, how="base", kind="bytes"):
    return (PLAINTEXT, label, label, kind, 0, how, glue, f".encrypt().plaintext({glue})")


def body(row, trial_, inline=False, key=PLAINTEXT):
    recv, before = RECEIVERS[key]
    return rust_runs.test_body(7, key, row, trial_, recv, before, inline)


class TestBodyTest(unittest.TestCase):
    def test_passing_the_value_is_its_own_counted_statement(self):
        lines = body({"type": "Vec<u8>", "kind": "bytes", "code": ".encrypt().plaintext(&x)"}, trial("Vec<u8>", "&x"))
        self.assertEqual(lines[:5], ["#[tokio::test]", "async fn run_7() {",
                                     "    // esdk/encrypt.plaintext: Vec<u8> passed as .encrypt().plaintext(&x)",
                                     '    let mut r = Report::new("run_7");', "    let x = plaintext_bytes();"])
        self.assertEqual(lines[5:], [
            "    let pre = aws_esdk::Client::default().encrypt();",
            "    let size = plaintext_bytes().len();",
            "    let start = allocated();",
            "    let built = pre.plaintext(&x);",
            "    r.copied(allocated() - start, size);",
            "    let result = built.keyring(raw_aes_keyring()).send().await;",
            "    check_encrypt(&mut r, result).await;",
            "}"])

    def test_inline_puts_the_setter_in_the_finishing_statement(self):
        lines = body({"type": "PathBuf", "kind": "path", "code": "x"},
                     trial("PathBuf", "&std::fs::read(x).unwrap()", kind="path"), inline=True)
        self.assertIn("    let result = pre.plaintext(&std::fs::read(x).unwrap()).keyring(raw_aes_keyring()).send().await;",
                      lines)
        self.assertFalse(any("allocated()" in line for line in lines))

    def test_a_set_fix_calls_the_set_setter(self):
        lines = body({"type": "Vec<u8>", "kind": "bytes", "code": "x"}, trial("Vec<u8>", "Some(x)", how="set"))
        self.assertIn("    let built = pre.set_plaintext(Some(x));", lines)

    def test_a_pair_holds_the_key_and_the_value(self):
        key = "esdk/encrypt.encryption_context"
        lines = body({"type": "(String, String)", "kind": "pair", "code": "x"},
                     (key, "(String, String)", "String", "pair", 0, "pair", "x, y", ""), key=key)
        self.assertIn("    let x = CONTEXT_KEY.to_string();", lines)
        self.assertIn("    let y = CONTEXT_VALUE.to_string();", lines)
        self.assertIn("    let built = pre.encryption_context(x, y);", lines)

    def test_a_type_it_cannot_hold_only_records_why(self):
        lines = body({"type": "TcpStream", "kind": "reader", "code": "x"}, trial("TcpStream", "x", kind="reader"))
        self.assertEqual(lines[-2:], ['    r.skip("needs a network connection");', "}"])


def row(type_, calls, trial_line):
    return {"type": type_, "calls": calls, "code": ".encrypt().plaintext(&x)", "kind": "bytes", "trial": trial_line}


class WriteTest(unittest.TestCase):
    TRIALS = [trial("Vec<u8>", "&x"), trial("Bytes", "&x")]
    ROWS = {PLAINTEXT: [row("Vec<u8>", 0, 4), row("Bytes", 0, 5), row("char", None, None)],
            "not/an.option": [row("Vec<u8>", 0, 4)]}

    def test_each_row_that_compiled_gets_a_test_at_the_line_it_records(self):
        text, tests = rust_runs.write(self.ROWS, self.TRIALS, RECEIVERS, 4)
        lines = text.split("\n")
        self.assertEqual(sorted(tests), ["run_0", "run_1"])
        for name, (key, label, line) in tests.items():
            self.assertEqual(lines[line - 1], f"async fn {name}() {{")
            self.assertEqual(lines[line], f"    // {key}: {label} passed as .encrypt().plaintext(&x)")
        self.assertEqual(tests["run_1"][:2], (PLAINTEXT, "Bytes"))
        self.assertIn("    let x = bytes::Bytes::from(plaintext_bytes());", text)

    def test_a_test_that_did_not_compile_is_replaced_by_one_that_says_so(self):
        text, tests = rust_runs.write(self.ROWS, self.TRIALS, RECEIVERS, 4, {"run_0": "skip"})
        lines = text.split("\n")
        line = tests["run_0"][2]
        self.assertEqual(lines[line - 1:line + 3], [
            "async fn run_0() {", "    // esdk/encrypt.plaintext: Vec<u8> passed as .encrypt().plaintext(&x)",
            '    Report::new("run_0").skip("this test did not compile");', "}"])


class ReadTest(unittest.TestCase):
    def test_run_lines_are_read_even_after_the_harness_text(self):
        stdout = "\n".join(["running 2 tests", 'test run_0 ... RUN run_0 {"builds":true,"same":false}',
                            'RUN run_1 {"skipped":"needs a network connection"}', "ok", "RUN run_2 not json"])
        self.assertEqual(rust_runs.read(stdout), {"run_0": {"builds": True, "same": False},
                                                  "run_1": {"skipped": "needs a network connection"}})


if __name__ == "__main__":
    unittest.main()
