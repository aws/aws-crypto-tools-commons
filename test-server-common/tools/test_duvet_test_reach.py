"""Run with: python3 -m unittest discover -s test-server-common/tools"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import duvet_test_reach as reach


def region(source, annotation_line):
    """The region of the annotation stack that ends on `annotation_line`."""
    stacks = reach.annotation_stacks(source.splitlines(), "x.rs")
    stops = {first: last for first, last, _ in stacks}
    return reach.region_after(reach.code_lines(source), annotation_line, stops)


class RegionTest(unittest.TestCase):

    def test_a_statement_ends_at_its_semicolon(self):
        source = """fn f() {
    //= spec/a.md#s
    //# A MUST b.
    let x = g(
        1,
    );
    let y = 2;
}
"""
        self.assertEqual((4, 6), region(source, 3))

    def test_a_block_runs_through_its_else(self):
        source = """fn f() {
    //= spec/a.md#s
    //# A MUST b.
    if a {
        b();
    } else {
        c();
    }
    d();
}
"""
        self.assertEqual((4, 8), region(source, 3))

    def test_a_match_arm_ends_at_its_comma(self):
        source = """fn f() {
    match x {
        //= spec/a.md#s
        //# A MUST b.
        1 => g(),
        2 => h(),
    }
}
"""
        self.assertEqual((5, 5), region(source, 4))

    def test_a_tail_expression_ends_with_the_block(self):
        source = """fn f() -> u8 {
    //= spec/a.md#s
    //# A MUST b.
    g()
        .h()
}
"""
        self.assertEqual((4, 5), region(source, 3))

    def test_the_next_annotation_ends_a_region(self):
        source = """fn f() {
    //= spec/a.md#s
    //# A MUST b.
    let r = c
        .d()
        //= spec/a.md#s
        //# C MUST d.
        .e();
}
"""
        self.assertEqual((4, 5), region(source, 3))

    def test_an_annotation_inside_the_block_does_not_end_it(self):
        source = """fn f() {
    match k {
        //= spec/a.md#s
        //# A MUST b.
        kdf => {
            //= spec/a.md#s
            //# C MUST d.
            hkdf(kdf)
        }
        _ => g(),
    }
}
"""
        self.assertEqual((5, 9), region(source, 4))
        self.assertEqual((8, 8), region(source, 7))

    def test_an_annotation_at_the_end_of_a_block_has_no_region(self):
        source = """fn f() {
    if a {
        b();
    } else {
        //= spec/a.md#s
        //# A MUST b.
    }
}
"""
        self.assertIsNone(region(source, 6))

    def test_stacks_with_only_blank_lines_between_share_the_next_statement(self):
        source = """fn f() {
    //= spec/a.md#s
    //# A MUST b.

    // a comment
    //= spec/a.md#s
    //# C MUST d.
    let x = 1;
}
"""
        self.assertEqual((8, 8), region(source, 3))

    def test_commas_in_type_arguments_and_strings_end_nothing(self):
        source = """fn f() {
    //= spec/a.md#s
    //# A MUST b.
    let m: HashMap<String, u8> = HashMap::from([(
        "a, }".to_string(), 'x' as u8)]);
}
"""
        self.assertEqual((4, 5), region(source, 3))


LIBRARY = """pub fn encrypt(x: u8) -> u8 {
    //= spec/doc.md#sec
    //# The thing MUST be blue.
    let blue = paint(x);

    //= spec/doc.md#sec
    //# The box MUST be red.
    let red = paint(blue);

    //= spec/doc.md#sec
    //= type=implication
    //# The lid MUST be green.
    red
}

//= spec/doc.md#sec
//# The jar MUST be shut.
pub struct Jar {
    shut: bool,
}

pub fn skipped_feature() {
    //= spec/doc.md#sec
    //# The cap MUST be tight.
    tighten();
}

pub fn not_recorded() {
    //= spec/doc.md#sec
    //# The pen MUST be capped.
    cap();
}

pub async fn tail() -> u8 {
    //= spec/doc.md#sec
    //# The tail MUST wag.
    wag()
}
"""

LOCAL_TESTS = """mod helpers;

fn check_blue() {
    //= spec/doc.md#sec
    //= type=test
    //# The thing MUST be blue.
    assert_eq!(encrypt(1), 1);
}

#[test]
fn blue() {
    check_blue();
}

#[tokio::test]
async fn red() {
    //= spec/doc.md#sec
    //= type=test
    //# The box MUST be red.
    assert_eq!(encrypt(2), 2);
}

#[test]
fn green() {
    //= spec/doc.md#sec
    //= type=test
    //# The lid MUST be green.
    encrypt(3);
}

#[test]
fn tail() {
    //= spec/doc.md#sec
    //= type=test
    //# The tail MUST wag.
    tail();
}

#[test]
fn jar() {
    //= spec/doc.md#sec
    //= type=test
    //# The jar MUST be shut.
    Jar { shut: true };
}
"""

SHARED_TESTS = """package x;

class SampleTests {

    @ParameterizedTest(name = "{0}")
    @MethodSource("languageServers")
    void cap(LanguageServerTarget languageServer) {
        //= spec/doc.md#sec
        //= type=test
        //# The cap MUST be tight.
        FeatureGate.require(Set.of("caps"), languageServer);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("languageServers")
    void pen(LanguageServerTarget languageServer) {
        //= specification/doc.md#sec
        //= type=test
        //# The pen MUST be capped.
        Ops.cap(languageServer);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("languageServers")
    void boxIsRed(LanguageServerTarget languageServer) {
        //= specification/doc.md#sec
        //= type=test
        //# The box MUST be red.
        Ops.encrypt(languageServer);
    }
}
"""


def row(test, source, status="passed", lines=(), **extra):
    return json.dumps({"test": test, "source": source, "language": "rust",
                       "repository": "aws/lib", "commit": "abc", "status": status,
                       "files": {"src/lib.rs": list(lines)}, **extra})


COVERAGE = [
    row("lib::sample::blue", "local", lines=[1, 4]),
    row("lib::sample::red", "local", lines=[1, 4]),
    row("lib::sample::tail", "local", lines=[34, 38]),
    row("x.SampleTests#cap(LanguageServerTarget)", "test-server", "skipped", reason="feature caps unsupported"),
    # A parameterized case: only its JUnit unique ID names the method.
    row("x.SampleTests#[1] rust", "test-server", lines=[1, 4, 8],
        junit_id="[engine:junit-jupiter]/[class:x.SampleTests]/[test-template:boxIsRed(x.T)]"
                 "/[test-template-invocation:#1]"),
]

# Every line of LIBRARY that holds code coverage could count, except the
# struct, which has none, and the tail expression `wag()`, which counts on
# its closing brace.
LCOV = "SF:src/lib.rs\n" + "".join(f"DA:{n},1\n" for n in (1, 4, 8, 13, 22, 25, 28, 31, 34, 38)) + "end_of_record\n"


class CheckTest(unittest.TestCase):

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        files = {"lib/src/lib.rs": LIBRARY, "lib/tests/sample.rs": LOCAL_TESTS,
                 "commons/tests/x/SampleTests.java": SHARED_TESTS,
                 "rust.jsonl": "\n".join(COVERAGE) + "\n", "rust.lcov": LCOV}
        for name, text in files.items():
            (self.root / name).parent.mkdir(parents=True, exist_ok=True)
            (self.root / name).write_text(text)

    def run_check(self, *extra, coverage="rust.jsonl"):
        out = self.root / "out.json"
        code = reach.main([
            "--language", "rust", "--library", "lib", "--repository", "aws/lib",
            "--repo-root", str(self.root / "lib"), "--source", "src",
            "--local-tests", "tests", "--crate", "lib",
            "--commons-root", str(self.root / "commons"), "--shared-tests", "tests",
            "--coverage", str(self.root / coverage), "--lcov", str(self.root / "rust.lcov"),
            "--prefix", "specification/=spec/", "--out", str(out), *extra])
        report = json.loads(out.read_text())
        states = {(f["source"], f["requirement"]["quote"]): f["state"] for f in report["findings"]}
        return code, report, states

    def test_each_state(self):
        code, report, states = self.run_check()
        self.assertEqual({
            ("local", "The thing MUST be blue."): reach.OK,
            ("local", "The box MUST be red."): reach.NEVER,
            ("local", "The jar MUST be shut."): reach.NO_REGION,
            ("local", "The tail MUST wag."): reach.OK,
            ("test-server", "The cap MUST be tight."): reach.NOT_RUN,
            ("test-server", "The pen MUST be capped."): reach.NOT_RUN,
            ("test-server", "The box MUST be red."): reach.OK,
        }, states)
        self.assertEqual({"implication or exception only": 1}, report["skipped"])
        self.assertEqual(1, code, "a test that never reaches its code fails the check")

    def test_a_skipped_run_reports_its_reason(self):
        _, report, _ = self.run_check()
        cap = next(f for f in report["findings"] if "cap MUST" in f["requirement"]["quote"])
        self.assertEqual("feature caps unsupported", cap["detail"])

    def test_an_annotation_above_a_test_belongs_to_that_test(self):
        tests = self.root / "lib" / "tests" / "sample.rs"
        tests.write_text(tests.read_text().replace("""#[tokio::test]
async fn red() {
    //= spec/doc.md#sec
    //= type=test
    //# The box MUST be red.
""", """//= spec/doc.md#sec
//= type=test
//# The box MUST be red.
#[tokio::test]
async fn red() {
"""))
        _, report, states = self.run_check()
        red = next(f for f in report["findings"] if f["source"] == "local" and "box" in f["requirement"]["quote"])
        self.assertEqual(["sample::red"], red["tests"])
        self.assertEqual(reach.NEVER, red["state"])

    def test_an_annotation_in_a_block_comment_is_an_error(self):
        tests = self.root / "lib" / "tests" / "sample.rs"
        tests.write_text(tests.read_text().replace("#[test]\nfn jar()", "/*\n#[test]\nfn jar()") + "*/\n")
        code, report, states = self.run_check()
        self.assertNotIn(("local", "The jar MUST be shut."), states)
        self.assertEqual(["tests/sample.rs:42: test annotation is in a /* */ comment, so no test runs it"],
                         report["errors"])
        self.assertEqual(1, code)

    def test_a_language_with_no_coverage_file_is_no_coverage(self):
        code, _, states = self.run_check(coverage="missing.jsonl")
        self.assertEqual(reach.NO_COVERAGE, states[("local", "The box MUST be red.")])
        self.assertEqual(0, code)

    def test_changed_mode_checks_only_changed_annotations(self):
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]
        lib = self.root / "lib"
        subprocess.run(git + ["init", "-q", str(lib)], check=True)
        subprocess.run(git + ["-C", str(lib), "add", "."], check=True)
        subprocess.run(git + ["-C", str(lib), "commit", "-qm", "base"], check=True)
        base = subprocess.run(["git", "-C", str(lib), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()
        tests = lib / "tests" / "sample.rs"
        tests.write_text(tests.read_text().replace("assert_eq!(encrypt(2), 2);", "assert_eq!(encrypt(2), 3);")
                         .replace("//# The box MUST be red.", "//# The box MUST be red. "))
        subprocess.run(git + ["-C", str(lib), "commit", "-qam", "change"], check=True)
        _, report, states = self.run_check("--changed-since", f"library={base}")
        self.assertEqual("changed", report["mode"])
        self.assertEqual({("local", "The box MUST be red."): reach.NEVER}, states)

    def test_changed_mode_reports_only_errors_on_changed_lines(self):
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]
        lib = self.root / "lib"
        tests = lib / "tests" / "sample.rs"
        tests.write_text(tests.read_text().replace("#[test]\nfn jar()", "/*\n#[test]\nfn jar()") + "*/\n")
        subprocess.run(git + ["init", "-q", str(lib)], check=True)
        subprocess.run(git + ["-C", str(lib), "add", "."], check=True)
        subprocess.run(git + ["-C", str(lib), "commit", "-qm", "base"], check=True)
        base = subprocess.run(["git", "-C", str(lib), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()
        _, report, _ = self.run_check("--changed-since", f"library={base}")
        self.assertEqual([], report["errors"])
        tests.write_text(tests.read_text().replace("//# The jar MUST be shut.", "//# The jar MUST be shut. "))
        subprocess.run(git + ["-C", str(lib), "commit", "-qam", "change"], check=True)
        _, report, _ = self.run_check("--changed-since", f"library={base}")
        self.assertEqual(1, len(report["errors"]))


if __name__ == "__main__":
    unittest.main()
