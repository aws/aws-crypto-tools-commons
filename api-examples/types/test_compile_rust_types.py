"""Tests for finding the names in a type that still need a path, and for picking each type's call."""
import os
import unittest
from pathlib import Path
from unittest import mock

import compile_rust_types as crt
from compile_rust_types import bare_names


class BareNamesTest(unittest.TestCase):
    def test_names_with_a_path_are_left_alone(self):
        self.assertEqual(bare_names("Option<&Blob>"), ["Blob"])
        self.assertEqual(bare_names("std::sync::Arc<aws_sdk_kms::Client>"), [])
        self.assertEqual(bare_names("HashMap<String, String>"), ["HashMap"])


class CargoTest(unittest.TestCase):
    def run_cargo(self, *args, env=None):
        scratch = object.__new__(crt.Scratch)
        scratch.dir, scratch.target = Path("/scratch"), Path("/rust/esdk/target")
        with mock.patch.object(crt.subprocess, "run") as run:
            scratch.cargo(*args, env=env)
        return run.call_args

    def test_the_target_dir_goes_before_the_test_binarys_options(self):
        self.assertEqual(self.run_cargo("test", "--test", "runs", "--", "--test-threads=1").args[0],
                         ["cargo", "test", "--test", "runs", "--target-dir", "/rust/esdk/target", "--", "--test-threads=1"])
        self.assertEqual(self.run_cargo("build", "--lib").args[0],
                         ["cargo", "build", "--lib", "--target-dir", "/rust/esdk/target"])

    def test_env_adds_to_the_callers_environment(self):
        env = self.run_cargo("test", env={"TMPDIR": "/scratch/tmp"}).kwargs["env"]
        self.assertEqual((env["TMPDIR"], env["PATH"]), ("/scratch/tmp", os.environ["PATH"]))


def trial(key, label, cost, call):
    return (key, label, label, "bytes", cost, "base", "x", call)


class BestRowsTest(unittest.TestCase):
    TRIALS = [trial("k", "Vec<u8>", 1, ".a(x.clone())"), trial("k", "Vec<u8>", 0, ".a(&x)"),
              trial("k", "Vec<u8>", 0, ".a(x)"), trial("k", "char", 0, ".a(x)"), trial("k", "Bytes", 2, ".a(x.f().g())")]

    def test_each_type_keeps_its_cheapest_call_that_compiled(self):
        rows = crt.best_rows(self.TRIALS, failed={1: ["error"], 3: ["error"]})["k"]
        first = crt.TRIALS_FIRST_LINE
        self.assertEqual(rows, [
            {"type": "Vec<u8>", "calls": 0, "code": ".a(x)", "fix": "x", "kind": "bytes", "trial": first + 2},
            {"type": "Bytes", "calls": 2, "code": ".a(x.f().g())", "fix": "x", "kind": "bytes", "trial": first + 4},
            {"type": "char", "calls": None, "code": "", "kind": "bytes", "trial": None}])

    def test_of_two_calls_that_cost_the_same_the_first_wins(self):
        rows = crt.best_rows(self.TRIALS, failed={})["k"]
        self.assertEqual(rows[0]["code"], ".a(&x)")

    def test_a_trials_line_is_where_trials_text_puts_it(self):
        lines = crt.trials_text(["fn t0() {}", "fn t1() {}"]).split("\n")
        self.assertEqual(lines[crt.TRIALS_FIRST_LINE - 1], "fn t0() {}")


if __name__ == "__main__":
    unittest.main()
