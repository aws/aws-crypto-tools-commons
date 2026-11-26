// Run with: node --test dashboard/pr-review/review.test.js
// Tests review.js, then runs index.html against a stand-in GitHub and stand-ins for the page's elements.
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const R = require("./review.js");

// ---------- review.js ----------
test("a pull request is a URL, owner/repo#N, or #N for commons", () => {
  assert.deepStrictEqual(R.parsePR("https://github.com/aws/aws-crypto-tools-rust/pull/179/files"), { repo: "aws/aws-crypto-tools-rust", n: 179 });
  assert.deepStrictEqual(R.parsePR("aws/aws-crypto-tools-java#15"), { repo: "aws/aws-crypto-tools-java", n: 15 });
  assert.deepStrictEqual(R.parsePR("#94"), { repo: "aws/aws-crypto-tools-commons", n: 94 });
  assert.strictEqual(R.parsePR("main"), null);
});

test("each diff row gets its line number on each side", () => {
  const rows = R.diffRows("@@ -10,3 +10,4 @@ fn f() {\n a\n-b\n+c\n+d\n e\n\\ No newline at end of file\n@@ -40 +41 @@\n-x\n+y");
  assert.deepStrictEqual(rows.map(r => [r.kind, r.old, r.new, r.text]), [
    ["hunk", null, null, "@@ -10,3 +10,4 @@ fn f() {"], ["ctx", 10, 10, "a"], ["del", 11, null, "b"], ["add", null, 11, "c"],
    ["add", null, 12, "d"], ["ctx", 12, 13, "e"], ["hunk", null, null, "@@ -40 +41 @@"], ["del", 40, null, "x"], ["add", null, 41, "y"]]);
});

// Duvet's rule: annotations with only blank lines or comments between them share the code after the last one.
test("each //= target starts an annotation, and annotations in a row share the first code line after them", () => {
  const blocks = R.annotations([
    "fn f() {",
    "    //= spec/a.md#one",
    "    //= type=implication",
    "    //# The keyring MUST",
    "    //# do a thing.",
    "    //= spec/b.md#two",
    "    //# It MUST NOT fail.",
    "",
    "    // a plain comment",
    "    do_it();",
    "}"].join("\n"));
  assert.deepStrictEqual(blocks.map(b => [b.target, b.type, b.quote, b.start, b.end, b.code]), [
    ["spec/a.md#one", "implication", "The keyring MUST do a thing.", 2, 5, 10],
    ["spec/b.md#two", "implementation", "It MUST NOT fail.", 6, 7, 10]]);
  assert.strictEqual(R.annotations("//= spec/a.md#one\n//# A MUST.\nlet x = 1;\n//= spec/b.md#two\n//# B MUST.\nlet y = 2;")[0].code, 3);
});

test("tests are found by their test attribute, in Rust and Java", () => {
  const found = R.testFunctions({
    "mpl/tests/a.rs": "fn helper() {}\n#[test]\nfn works() {}\n#[tokio::test]\nasync fn also_works() {}",
    "T.java": "@Test\nvoid javaWorks() {}",
  });
  assert.deepStrictEqual(found, { works: { file: "mpl/tests/a.rs", line: 3 }, also_works: { file: "mpl/tests/a.rs", line: 5 },
    javaWorks: { file: "T.java", line: 2 } });
});

test("a JUnit id names the test class, method and case; other names are not JUnit ids", () => {
  assert.deepStrictEqual(R.junitId("[engine:junit-jupiter]/[class:a.b.FooTest]/[test-template:bar(java.lang.String)]/[test-template-invocation:#2]"),
    { cls: "a.b.FooTest", method: "bar", run: 2 });
  assert.strictEqual(R.junitId("aws-crypto-mpl::test_x::works"), null);
  assert.strictEqual(R.shortTest("aws-crypto-mpl::test_x::works"), "works");
  assert.strictEqual(R.shortTest("a.FooTest#[aws-kms] does a thing rust-v1"), "does a thing rust-v1");
});

test("a short path keeps as many folders as it takes to tell two files apart", () => {
  assert.deepStrictEqual(R.shortPaths(["mpl/src/aws_kms/keyring.rs", "esdk/test-server/src/keyring.rs", "mpl/src/lib.rs"]),
    { "mpl/src/aws_kms/keyring.rs": "aws_kms/keyring.rs", "esdk/test-server/src/keyring.rs": "src/keyring.rs", "mpl/src/lib.rs": "lib.rs" });
});

test("public items: a new method names its impl's type, a removed and re-added one changed, and tests are skipped", () => {
  const text = "pub struct KBuilder {}\n\nimpl KBuilder {\n    pub fn key_id(self) -> Self {\n    }\n    pub(crate) fn hidden() {}\n    pub fn grant(self, g: String) -> Self {\n}\n}";
  const rows = [{ kind: "add", new: 1, text: "pub struct KBuilder {}" }, { kind: "add", new: 4, text: "    pub fn key_id(self) -> Self {" },
    { kind: "add", new: 6, text: "    pub(crate) fn hidden() {}" }, { kind: "del", old: 7, text: "    pub fn grant(self) -> Self {" },
    { kind: "add", new: 7, text: "    pub fn grant(self, g: String) -> Self {" }];
  assert.deepStrictEqual(R.publicItems("mpl/src/k.rs", rows, text).map(i => [i.side, i.kind, i.name, i.owner, i.line]), [
    ["added", "struct", "KBuilder", null, 1], ["added", "fn", "key_id", "KBuilder", 4], ["changed", "fn", "grant", "KBuilder", 7]]);
  assert.deepStrictEqual(R.publicItems("mpl/tests/k.rs", rows, text), []);
  assert.deepStrictEqual(R.publicItems("mpl/test-server/src/k.rs", rows, text), []);
});

test("a public use is named by its path", () => {
  const rows = [{ kind: "add", new: 1, text: "pub use crate::aws_kms::keyring::{AwsKmsKeyring, AwsKmsKeyringBuilder};" }];
  assert.deepStrictEqual(R.publicItems("mpl/src/keyring/mod.rs", rows, rows[0].text).map(i => [i.kind, i.name]),
    [["use", "crate::aws_kms::keyring::{AwsKmsKeyring, AwsKmsKeyringBuilder}"]]);
});

const API = (id, options, span) => ({ lib: "mpl", id, name: id, span, options });
const OPT = (name, takes, span) => ({ name, takes, span });
test("the API diff lists new APIs, and options added, removed or taking another type", () => {
  const main = { apis: [API("raw-aes-keyring", [OPT("key_name", "impl Into<String>"), OPT("wrapping_alg", "AesWrappingAlg")])] };
  const pr = { apis: [API("raw-aes-keyring", [OPT("key_name", "&str"), OPT("key_namespace", "impl Into<String>")]), API("aws-kms-keyring", [OPT("kms_key_id", "impl Into<String>")])] };
  const d = R.apiDiff(main, pr);
  assert.deepStrictEqual(d.added.map(a => a.id), ["aws-kms-keyring"]);
  assert.deepStrictEqual(d.options.added.map(o => o.option), ["key_namespace", "kms_key_id"]);
  assert.deepStrictEqual(d.options.changed.map(o => [o.option, o.was, o.takes]), [["key_name", "impl Into<String>", "&str"]]);
  assert.deepStrictEqual(d.options.removed.map(o => o.option), ["wrapping_alg"]);
});

test("a line inside an option's setter belongs to that option, and a line in the type belongs to the API", () => {
  const data = { apis: [API("aws-kms-keyring", [OPT("kms_key_id", "", { file: "k.rs", line: 10, end: 13 })], { file: "k.rs", line: 2, end: 4 })] };
  assert.deepStrictEqual(R.apiAt(data, "k.rs", 12).map(a => a.option), ["kms_key_id"]);
  assert.deepStrictEqual(R.apiAt(data, "k.rs", 3).map(a => a.option), [null]);
  assert.deepStrictEqual(R.apiAt(data, "k.rs", 20), []);
});

const lines = obj => new Map(Object.entries(obj).map(([f, l]) => [f, new Map(Object.entries(l).map(([n, h]) => [+n, h]))]));
test("a line runs if any coverage source ran it, and is not code if none counts it", () => {
  const local = lines({ "a.rs": { 1: 0, 2: 0 } }), server = lines({ "a.rs": { 2: 5 } });
  assert.strictEqual(R.lineRun([local, server], "a.rs", 1), "not-run");
  assert.strictEqual(R.lineRun([local, server], "a.rs", 2), "run");
  assert.strictEqual(R.lineRun([local, server], "a.rs", 3), "none");
});

// One library file with three added lines, and evidence that says all is well.
const FILE = { filename: "mpl/src/k.rs", code: true, rows: R.diffRows("@@ -1,0 +1,3 @@\n+fn a() {\n+    b();\n+}") };
const TEST = { filename: "mpl/tests/t.rs", code: true, rows: R.diffRows("@@ -1,0 +1,1 @@\n+    helper();") };
const good = () => ({
  checks: [{ name: "Build", status: "completed", conclusion: "success" }],
  local: lines({ "mpl/src/k.rs": { 1: 3, 2: 3 }, "mpl/tests/t.rs": { 1: 0 } }),
  server: null,
  branches: new Map([["mpl/src/k.rs", new Map([[2, new Map([["0,0", 3], ["0,1", 1]])]])]]),
  mutants: new Map([["mpl/src/k.rs", new Map([[2, [{ status: "killed" }, { status: "unviable" }]]])]]),
  api: {},
});
const ids = flags => flags.map(f => f.id);

test("nothing to look at when every changed line runs, every branch is taken, every mutant is caught and checks pass", () => {
  assert.deepStrictEqual(R.findFlags([FILE, TEST], good()), []);
});

test("a changed library line no test runs is flagged once, not also for its branches, and a test file's line is not", () => {
  const d = good();
  d.local.get("mpl/src/k.rs").set(1, 0);
  d.branches.get("mpl/src/k.rs").set(1, new Map([["0,0", 0]]));
  const f = R.findFlags([FILE, TEST], d);
  assert.deepStrictEqual(ids(f), ["lines"]);
  assert.deepStrictEqual(f[0].lines, [{ file: "mpl/src/k.rs", line: 1, code: true }]);
});

test("a test server's code is left out of the line checks, as the coverage checks in CI leave it out", () => {
  const server = { filename: "mpl/test-server/src/handlers.rs", code: true, rows: R.diffRows("@@ -1,0 +1,1 @@\n+fn h() {}") };
  const d = good();
  d.local.set("mpl/test-server/src/handlers.rs", new Map([[1, 0]]));
  assert.deepStrictEqual(ids(R.findFlags([FILE, server], d)), []);
});

test("a branch no test takes is flagged on a line that runs", () => {
  const d = good();
  d.branches.get("mpl/src/k.rs").get(2).set("0,1", 0);
  assert.deepStrictEqual(ids(R.findFlags([FILE], d)), ["branches"]);
});

test("a mutant that survives, or sits on a line no test runs, is flagged with its line", () => {
  const d = good();
  d.mutants.get("mpl/src/k.rs").set(1, [{ status: "survived" }, { status: "not_covered" }]);
  const f = R.findFlags([FILE], d);
  assert.deepStrictEqual(f.map(x => [x.id, x.text, x.lines]), [["mutants", "2 mutants no test catches", [{ file: "mpl/src/k.rs", line: 1 }]]]);
});

test("failed and running checks, missing results, a duvet test that misses its code, test server failures, conformance and API changes are flagged", () => {
  const d = good();
  d.checks.push({ name: "Mutation", status: "completed", conclusion: "failure" }, { name: "Slow", status: "in_progress", conclusion: null });
  d.local = null;
  d.mutants = null;
  const req = { target: "spec/a.md#x", quote: "It MUST." };
  d.reach = [{ finding: "r:0", path: "mpl/src/k.rs", from: 1, to: 2, state: "never-reaches", requirement: req },
    { finding: "r:0", path: "mpl/src/k.rs", from: 5, to: 6, state: "never-reaches", requirement: req },
    { finding: "r:1", path: "mpl/src/k.rs", from: 1, to: 1, state: "ok", requirement: req }];
  d.servers = [{ product: "mpl", failed: [{ cls: "T", name: "x" }] }];
  d.conformance = [{ crate: "mpl", result: "FAIL", open: [{ id: "a" }] }];
  d.api = { items: [{ file: "mpl/src/k.rs", line: 1, side: "added", kind: "fn", name: "a", owner: null }] };
  const f = R.findFlags([FILE], d);
  assert.deepStrictEqual(ids(f), ["checks", "running", "no-coverage", "no-mutants", "reach", "servers", "conformance", "api"]);
  assert.strictEqual(f.find(x => x.id === "reach").text, "1 duvet test never runs the code it cites");
  assert.deepStrictEqual(f.find(x => x.id === "api").items, ["a added"]);
});

test("a line's evidence has its annotation, its reach result and its comments, by side", () => {
  const data = { ...good(), blocks: new Map([["mpl/src/k.rs", R.annotations("//= spec/a.md#x\n//# It MUST.\nfn a() {")]]),
    reach: [{ path: "mpl/src/k.rs", from: 3, to: 4, state: "ok", requirement: {} }],
    comments: new Map([["mpl/src/k.rs", new Map([["R3", [{ body: "new" }]], ["L3", [{ body: "old" }]]])]]) };
  const ev = R.lineEvidence(data, "mpl/src/k.rs", 3);
  assert.deepStrictEqual([ev.duvet.map(b => b.target), ev.reach.length, ev.comments.map(c => c.body)], [["spec/a.md#x"], 1, ["new"]]);
  assert.deepStrictEqual(R.lineEvidence(data, "mpl/src/k.rs", 3, "del").comments.map(c => c.body), ["old"]);
});

// ---------- the page ----------
const read = f => fs.readFileSync(path.join(__dirname, f), "utf8");
const PAGE = read("../test-servers/loader.js") + "\n" + read("review.js") + "\n" + read("index.html").split("<script>")[1].split("</script>")[0]
  + "\nglobalThis.__page = { get state() { return state; } };";

// A zip of stored (not compressed) files, like an artifact download.
function zipOf(files) {
  const locals = [], centrals = [];
  let offset = 0;
  for (const [name, text] of Object.entries(files)) {
    const n = Buffer.from(name), data = Buffer.from(text), local = Buffer.alloc(30), central = Buffer.alloc(46);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(n.length, 26);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(n.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, n, data);
    centrals.push(central, n);
    offset += local.length + n.length + data.length;
  }
  const dir = Buffer.concat(centrals), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(files).length, 8);
  end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(dir.length, 12);
  end.writeUInt32LE(offset, 16);
  const all = Buffer.concat([...locals, dir, end]);
  return all.buffer.slice(all.byteOffset, all.byteOffset + all.length);
}

const HEAD = "a".repeat(40), REPO = "aws/aws-crypto-tools-rust", PR = `repos/${REPO}/pulls/7`;
// A private method, so the PR changes no public item, and the local test that catches its mutant.
const SOURCE = "struct KBuilder {}\nimpl KBuilder {\n    fn key_id(self) -> Self {\n        //= spec/k.md#init\n        //# It MUST check.\n        check(self)\n    }\n}";
const TESTS = "#[test]\nfn checks() {\n    assert!(true);\n}";
const added = text => `@@ -0,0 +1,${text.split("\n").length} @@\n` + text.split("\n").map(l => "+" + l).join("\n");
const art = (id, name) => ({ id, name, expired: false, created_at: "2026-11-26T00:00:00Z", size_in_bytes: 10 });
const lcov = hits => `SF:mpl/src/k.rs\n${Object.entries(hits).map(([n, h]) => `DA:${n},${h}`).join("\n")}\nend_of_record\n`;
const results = mutants => JSON.stringify({ summary: { library: "mpl", scope: "changed", commit: HEAD }, mutants });

// A stand-in GitHub for one Rust PR with one file. Pass replies to change what it says.
function github(over = {}) {
  const page1 = "per_page=100&page=1";
  return {
    [PR]: { title: "feat(mpl): add K", html_url: "https://github.com/aws/aws-crypto-tools-rust/pull/7", draft: true, user: { login: "dev" },
      head: { sha: HEAD, ref: "k" }, base: { ref: "main" } },
    [`${PR}/files?${page1}`]: [{ filename: "mpl/src/k.rs", status: "added", additions: 8, deletions: 0, patch: added(SOURCE) },
      { filename: "mpl/tests/t.rs", status: "added", additions: 4, deletions: 0, patch: added(TESTS) }],
    [`repos/${REPO}/commits/${HEAD}/check-runs?${page1}`]: { check_runs: [{ id: 1, name: "Build", status: "completed", conclusion: "success" }] },
    [`repos/${REPO}/actions/runs?head_sha=${HEAD}&${page1}`]: { workflow_runs: [{ id: 50 }] },
    [`${PR}/comments?${page1}`]: [],
    [`repos/${REPO}/contents/mpl/src/k.rs?ref=${HEAD}`]: SOURCE,
    [`repos/${REPO}/contents/mpl/tests/t.rs?ref=${HEAD}`]: TESTS,
    [`repos/${REPO}/actions/runs/50/artifacts?${page1}`]: { artifacts: [art(1, "mutation-results-mpl"), art(2, "local-coverage-mpl")] },
    [`repos/${REPO}/actions/artifacts/1/zip`]: zipOf({ "results.json": results([{ file: "mpl/src/k.rs", line: 6, status: "killed", description: "replace check with ()", killed_by: "aws-crypto-mpl::t::checks" }]) }),
    [`repos/${REPO}/actions/artifacts/2/zip`]: zipOf({ "mpl.lcov": lcov({ 3: 4, 6: 4, 7: 4 }) }),
    ...over,
  };
}

// Opens the page on PR 7 against `replies`. Returns its elements, the requests it sent, and a click helper.
async function open(replies, query = "") {
  const sent = [];
  const fetch = async (url, opts = {}) => {
    const p = url.replace("https://api.github.com/", "");
    if (opts.method && opts.method !== "GET") {
      const body = JSON.parse(opts.body);
      sent.push({ method: opts.method, path: p, body });
      return { ok: true, status: 201, json: async () => ({ id: 9, user: { login: "me" }, html_url: "https://example.com/9", created_at: "2026-11-26", ...body }) };
    }
    const reply = replies[p];
    return { ok: reply !== undefined, status: reply === undefined ? 404 : 200, json: async () => structuredClone(reply),
      text: async () => (typeof reply === "string" ? reply : JSON.stringify(reply)), arrayBuffer: async () => reply };
  };
  const els = {};
  const el = id => els[id] || (els[id] = { innerHTML: "", value: "", scrollTop: 0, on: {}, classList: { add() {}, remove() {} },
    style: { setProperty() {} }, addEventListener(type, f) { this.on[type] = f; } });
  const storage = () => { const m = new Map([["github-dashboard-token", "t"]]); return { getItem: k => m.get(k) ?? null, setItem: (k, v) => m.set(k, v), removeItem: k => m.delete(k) }; };
  const session = storage();
  new Function("document", "fetch", "location", "localStorage", "sessionStorage", "history", "navigator", "addEventListener", "removeEventListener", PAGE)(
    { getElementById: el, querySelector: () => null, body: el("body") }, fetch, { search: `?pr=${encodeURIComponent(REPO + "#7")}${query}` },
    storage(), session, { replaceState() {} }, {}, () => {}, () => {});
  for (let i = 0; i < 300 && !(globalThis.__page.state && globalThis.__page.state.done && !globalThis.__page.state.loading.size); i++) await new Promise(r => setTimeout(r, 10));
  await new Promise(r => setTimeout(r, 30));
  // A click on an element in #id whose closest match for each selector in `matches` has that dataset.
  const click = (id, matches) => els[id].on.click({ preventDefault() {}, target: { closest: s => {
    const key = Object.keys(matches).find(k => s.split(", ").includes(k));
    return key ? { dataset: matches[key] } : null;
  } } });
  const clickLine = line => click("files", { "tr[data-r]": { f: "0", r: String(globalThis.__page.state.files[0].rows.findIndex(r => r.new === line)) } });
  return { els, sent, click, clickLine, session, state: globalThis.__page.state };
}

test("a PR whose changed lines all run and whose mutants are all caught says there is nothing to look at", async () => {
  const page = await open(github());
  assert.match(page.els.top.innerHTML, /✓ Nothing to look at\. Every changed line runs in a test/);
  assert.doesNotMatch(page.els.top.innerHTML, /class="flags"/);
  assert.match(page.els.files.innerHTML, /No changed line needs a look\./);
  assert.doesNotMatch(page.els.files.innerHTML, /<tr class="add"/);
});

test("a PR from the link becomes the PR box that the other tabs share", async () => {
  const page = await open(github());
  assert.strictEqual(page.session.getItem("testServerSource"), `${REPO}#7`);
});

test("?line= opens a line the PR does not change, with the coverage of its file read too", async () => {
  const replies = github({
    [`repos/${REPO}/contents/mpl/src/other.rs?ref=${HEAD}`]: "fn a() {\n    b();\n}",
    [`repos/${REPO}/actions/artifacts/2/zip`]: zipOf({ "mpl.lcov": lcov({ 3: 4, 6: 4, 7: 4 }) + "SF:mpl/src/other.rs\nDA:2,5\nend_of_record\n" }),
  });
  const page = await open(replies, "&line=mpl%2Fsrc%2Fother.rs%3A2");
  assert.match(page.els.detail.innerHTML, /<h3>mpl\/src\/other\.rs:2<\/h3>/);
  assert.match(page.els.detail.innerHTML, /local tests ran it 5 times/);
  assert.match(page.els.files.innerHTML, /lines you opened/);
  const opened = page.els.files.innerHTML.split("<tr").find(r => r.includes('<td class="ln"></td><td class="ln">2</td>'));
  assert.match(opened, /class="src run"/);
});

test("the line box opens a changed line in place", async () => {
  const page = await open(github());
  page.els.where = { value: "mpl/src/k.rs:3" };
  page.els.files.on.submit({ preventDefault() {} });
  await new Promise(r => setTimeout(r, 20));
  assert.match(page.els.detail.innerHTML, /<h3>mpl\/src\/k\.rs:3<\/h3>/);
  assert.strictEqual(page.state.files.filter(f => f.extra).length, 0);
});

test("a mutant that survives is flagged, marked on its line, and explained in the line's pane", async () => {
  const page = await open(github({ [`repos/${REPO}/actions/artifacts/1/zip`]: zipOf({ "results.json": results([
    { file: "mpl/src/k.rs", line: 6, status: "survived", description: "replace check with ()", killed_by: null }]) }) }));
  assert.match(page.els.top.innerHTML, /<b>1 mutant no test catches<\/b><small>k\.rs:6<\/small>/);
  const row6 = page.els.files.innerHTML.split("<tr").find(r => /<td class="ln"><\/td><td class="ln">6<\/td>/.test(r));
  assert.match(row6, /class="m-bad"/);
  page.clickLine(6);
  assert.match(page.els.detail.innerHTML, /survived<\/span>: replace check with \(\)/);
  assert.match(page.els.detail.innerHTML, /every test that runs this line still passes/);
});

test("a changed line no test runs is flagged and drawn red, and one that runs is drawn green", async () => {
  const page = await open(github({ [`repos/${REPO}/actions/artifacts/2/zip`]: zipOf({ "mpl.lcov": lcov({ 3: 4, 6: 0, 7: 4 }) }) }));
  assert.match(page.els.top.innerHTML, /1 changed line run in no test/);
  const rows = page.els.files.innerHTML.split("<tr").slice(1);
  assert.match(rows.find(r => r.includes('<td class="ln">6</td>')), /class="src miss"/);
  assert.match(rows.find(r => r.includes('<td class="ln">7</td>')), /class="src run"/);
  // Only the lines to look at and two around them are drawn; GitHub shows the rest.
  assert.ok(!rows.some(r => r.includes('<td class="ln">3</td>')));
});

test("files with more gaps in testing come first, and a file with nothing to look at is not drawn", async () => {
  const replies = github({
    [`repos/${REPO}/actions/artifacts/2/zip`]: zipOf({ "mpl.lcov": lcov({ 3: 4, 6: 0, 7: 0 }) + "SF:mpl/src/j.rs\nDA:1,0\nend_of_record\n" }),
    [`repos/${REPO}/contents/mpl/src/j.rs?ref=${HEAD}`]: "fn j() {}",
  });
  replies[`${PR}/files?per_page=100&page=1`].unshift({ filename: "mpl/src/j.rs", status: "added", additions: 1, deletions: 0, patch: added("fn j() {}") });
  const page = await open(replies);
  const files = [...page.els.files.innerHTML.matchAll(/<span class="path">([^<]+)<\/span>/g)].map(m => m[1]);
  assert.deepStrictEqual(files, ["mpl/src/k.rs", "mpl/src/j.rs"]);
  assert.match(page.els.files.innerHTML, /<span class="path">mpl\/src\/k\.rs<\/span>[^]*?<span class="tag warn">2 gaps in testing<\/span>/);
});

test("a line's pane names its duvet requirement, and links the test that catches its mutant to that test's line", async () => {
  const page = await open(github());
  page.clickLine(6);
  assert.match(page.els.detail.innerHTML, /<code>spec\/k\.md#init<\/code>: It MUST check\./);
  assert.match(page.els.detail.innerHTML, /killed<\/span>: replace check with \(\) · caught by <a href="#" data-goto="1:2">checks<\/a>/);
  assert.match(page.els.detail.innerHTML, /local tests ran it 4 times/);
  page.click("detail", { "[data-goto]": { goto: "1:2" } });
  assert.match(page.els.detail.innerHTML, /<h3>mpl\/tests\/t\.rs:2<\/h3>/);
});

test("Comment posts a review comment on the clicked line of the head commit, and shows it", async () => {
  const page = await open(github());
  page.clickLine(3);
  page.els.comment = { value: "Should this take &str?" };
  page.click("detail", { "[data-post]": {} });
  await new Promise(r => setTimeout(r, 20));
  assert.deepStrictEqual(page.sent, [{ method: "POST", path: `${PR}/comments`,
    body: { body: "Should this take &str?", commit_id: HEAD, path: "mpl/src/k.rs", line: 3, side: "RIGHT" } }]);
  assert.match(page.els.detail.innerHTML, /<div>Should this take &amp;str\?<\/div>/);
});

test("the PR's own CI run gives the API at its head and merge base, and the page shows what the PR adds", async () => {
  const types = (api, more = {}) => zipOf({ "api-examples/types/rust-api.json": JSON.stringify(api), ...more });
  const replies = github({
    [`repos/${REPO}/actions/runs/50/artifacts?per_page=100&page=1`]: { artifacts: [art(1, "mutation-results-mpl"), art(2, "local-coverage-mpl"),
      art(71, "api-types-rust"), art(70, "api-types-rust-base")] },
    [`repos/${REPO}/actions/artifacts/71/zip`]: types({ apis: [{ lib: "mpl", id: "k", name: "K keyring", span: null,
      options: [{ name: "key_id", takes: "impl Into<String>", span: { file: "mpl/src/k.rs", line: 3, end: 7 } }] }] },
      { "dashboard/api-examples/types-rust.json": JSON.stringify({ apis: [], rows: {} }) }),
    [`repos/${REPO}/actions/artifacts/70/zip`]: types({ apis: [] }),
  });
  const page = await open(replies);
  assert.match(page.els.top.innerHTML, /<b>K keyring<\/b> is new: <code>key_id<\/code> takes <code>impl Into&lt;String&gt;<\/code>/);
  page.clickLine(5);
  assert.match(page.els.detail.innerHTML, /K keyring: option <code>key_id<\/code> · <a href="\.\.\/api-examples\/types\.html\?ref=main&amp;pr=aws%2Faws-crypto-tools-rust%237&amp;api=mpl%7Ck"/);
});

// ---------- the PR findings job ----------
const FINDING = (kind, level, file, line, more = {}) => ({ key: `${kind}:${line}`, kind, level, file, line, side: "RIGHT",
  title: kind, what: `${kind} here`, why: [], fix: null, rerun: [], patch: null, links: {}, ...more });

test("the findings become one flag per kind, blocking ones first, with no-line findings as items", () => {
  const flags = R.flagsFromFindings({ missing: ["mutation results"], findings: [
    FINDING("api-new", "warn", "mpl/src/k.rs", 1),
    FINDING("mutant-survived", "block", "mpl/src/k.rs", 4), FINDING("mutant-not-covered", "block", "mpl/src/k.rs", 9),
    FINDING("test-server-case-failed", "block", null, null, { what: "KTest failed" })] });
  assert.deepStrictEqual(flags.map(f => [f.id, f.level, f.text]), [
    ["mutants", "bad", "2 mutants no test catches"], ["servers", "bad", "1 test server case failed"],
    ["api", "note", "The public API changes"], ["missing:mutation results", "note", "No mutation results on this commit yet"]]);
  assert.deepStrictEqual(flags[0].lines, [{ file: "mpl/src/k.rs", line: 4 }, { file: "mpl/src/k.rs", line: 9 }]);
  assert.deepStrictEqual(flags[1].items, ["KTest failed"]);
});

test("a finding's text shows its code and its https links, and no other HTML", () => {
  assert.strictEqual(R.md("`>=` in [the spec](https://x.test/a?b=1&c=2#d), <b>, [run](javascript:alert(1))"),
    '<code>&gt;=</code> in <a href="https://x.test/a?b=1&amp;c=2#d" target="_blank">the spec</a>, &lt;b&gt;, [run](javascript:alert(1))');
});

test("the 👎 count of each kind of findings comment leaves out replies and other comments", () => {
  const c = (kind, down, more = {}) => ({ body: `x\n<!-- pr-findings {"key": "k", "kind": "${kind}"} -->`, reactions: { "-1": down, "+1": 0 }, ...more });
  assert.deepStrictEqual(R.noise([c("mutant-survived", 1), c("mutant-survived", 0), c("api-new", 1), c("api-new", 1),
    c("mutant-survived", 5, { in_reply_to_id: 3 }), { body: "a person's comment", reactions: { "-1": 9 } }]), [
    { kind: "api-new", comments: 2, down: 2, up: 0 }, { kind: "mutant-survived", comments: 2, down: 1, up: 0 }]);
});

function withFindings(findings, comments = []) {
  return github({
    [`repos/${REPO}/actions/runs/50/artifacts?per_page=100&page=1`]: { artifacts: [art(1, "mutation-results-mpl"), art(2, "local-coverage-mpl"), art(80, "pr-findings")] },
    [`repos/${REPO}/actions/artifacts/80/zip`]: zipOf({ "findings.json": JSON.stringify({ findings }) }),
    [`${PR}/comments?per_page=100&page=1`]: comments,
  });
}

test("with the findings job's file, the flags are its findings, and a line's pane shows why and how to run it", async () => {
  const f = FINDING("api-new", "warn", "mpl/src/k.rs", 6, { title: "New API", what: "New API: K keyring.",
    why: ["`key_id` takes [text](https://example.com/spec#ids)."], fix: "Run it.", rerun: ["cargo test"] });
  const page = await open(withFindings([f]));
  assert.match(page.els.top.innerHTML, /<b>The public API changes<\/b><small>k\.rs:6<\/small>/);
  page.clickLine(6);
  assert.match(page.els.detail.innerHTML, /<b class="warn">New API<\/b> <small class="sub">note<\/small>/);
  assert.match(page.els.detail.innerHTML, /<div class="sub"><code>key_id<\/code> takes <a href="https:\/\/example\.com\/spec#ids" target="_blank">text<\/a>\.<\/div><div><b>Fix:<\/b> Run it\.<\/div>/);
  assert.match(page.els.detail.innerHTML, /<pre class="code">cargo test<\/pre>/);
});

test("Not useful marks the finding's comment 👎", async () => {
  const f = FINDING("api-new", "warn", "mpl/src/k.rs", 6);
  const comment = { id: 41, path: "mpl/src/k.rs", line: 6, side: "RIGHT", user: { login: "github-actions[bot]" }, html_url: "https://example.com/41",
    body: `x\n<!-- pr-findings {"key": "${f.key}", "kind": "api-new"} -->`, reactions: { "-1": 2 } };
  const page = await open(withFindings([f], [comment]));
  page.clickLine(6);
  assert.match(page.els.detail.innerHTML, /data-down="41"[^>]*>👎 Not useful \(2\)/);
  page.click("detail", { "[data-down]": { down: "41" } });
  await new Promise(r => setTimeout(r, 20));
  assert.deepStrictEqual(page.sent, [{ method: "POST", path: `repos/${REPO}/pulls/comments/41/reactions`, body: { content: "-1" } }]);
  assert.match(page.els.detail.innerHTML, /👎 Not useful \(3\)/);
});
