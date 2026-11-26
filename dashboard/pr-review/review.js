// The PR review page's logic that needs no browser. It turns a pull request's diff, its files and its CI
// artifacts into one record per changed line, and into the short list of things a reviewer should look at.
// index.html loads this file; review.test.js tests it with node.
"use strict";

const FAILED_CHECK = new Set(["failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale"]);
const CODE_FILE = /\.(rs|java|kt|go|cs|py|ts|js|mjs|c|h|cc|cpp|hpp|dfy)$/;
// Tests and examples. A line in one that no test runs is not a gap in testing, so the page does not flag it.
const TEST_FILE = /(^|\/)(tests?|benches|examples)\/|_tests?\.rs$|Tests?\.java$|\.test\.js$/;
// Test server code. The coverage checks in CI leave it out, so the line and branch flags do too.
const TEST_SERVER_CODE = /(^|\/)test-server(-control)?\//;
// Mutation statuses that fail the mutation check: no test failed with the mutant on, or no test runs its line.
const BAD_MUTANT = new Set(["survived", "not_covered"]);

// A pull request from a URL, owner/repo#N, or #N for commons.
function parsePR(text, commons = "aws/aws-crypto-tools-commons") {
  const t = String(text || "").trim();
  const m = t.match(/github\.com\/([^/\s]+\/[^/\s]+)\/pull\/(\d+)/) || t.match(/^(?:([\w.-]+\/[\w.-]+))?#(\d+)$/);
  return m ? { repo: m[1] || commons, n: +m[2] } : null;
}

// The rows of one file's patch from GitHub's pull request files API.
// kind is "hunk" for an @@ line, "add", "del" or "ctx"; old and new are the line numbers on each side.
function diffRows(patch) {
  const rows = [], lines = String(patch || "").split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  let o = 0, n = 0;
  for (const line of lines) {
    const h = line.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (h) {
      o = +h[1];
      n = +h[2];
      rows.push({ kind: "hunk", old: null, new: null, text: line });
    } else if (line.startsWith("\\")) {
      // "\ No newline at end of file" belongs to the line before it.
    } else if (line.startsWith("+")) {
      rows.push({ kind: "add", old: null, new: n++, text: line.slice(1) });
    } else if (line.startsWith("-")) {
      rows.push({ kind: "del", old: o++, new: null, text: line.slice(1) });
    } else {
      rows.push({ kind: "ctx", old: o++, new: n++, text: line.slice(1) });
    }
  }
  return rows;
}

// The duvet annotations in a file: [{start, end, target, type, reason, quote, code}].
// start and end are the block's first and last lines. code is the first line after the block that is
// neither blank nor a comment, which is the line duvet ties the annotation to.
function annotations(text) {
  const lines = String(text || "").split("\n"), out = [];
  for (let i = 0; i < lines.length; i++) {
    const head = lines[i].match(/^\s*\/\/=\s*(\S+)\s*$/);
    if (!head) continue;
    const block = { start: i + 1, end: i + 1, target: head[1], type: "implementation", reason: null, quote: [], code: null };
    let j = i + 1;
    for (; j < lines.length; j++) {
      const meta = lines[j].match(/^\s*\/\/=\s*(type|reason|tracking-issue)=(.*)$/);
      const quote = lines[j].match(/^\s*\/\/#(?: (.*)|$)/);
      if (meta) {
        if (meta[1] === "type") block.type = meta[2].trim();
        if (meta[1] === "reason") block.reason = meta[2].trim();
      } else if (quote) {
        block.quote.push(quote[1] || "");
      } else {
        break;
      }
    }
    block.end = j;
    let k = j;
    while (k < lines.length && /^\s*(\/\/.*)?$/.test(lines[k])) k++;
    block.code = k < lines.length ? k + 1 : null;
    block.quote = block.quote.join(" ").trim();
    out.push(block);
    i = j - 1;
  }
  return out;
}

// The tests named in source files, as name -> {file, line}: Rust `fn name` after a test attribute, and
// Java methods after @Test. A mutant's killed_by and a per-test record name tests this way.
function testFunctions(files) {
  const out = {};
  for (const [file, text] of Object.entries(files)) {
    const lines = String(text).split("\n");
    let pending = false;
    lines.forEach((line, i) => {
      if (/#\[\s*(?:[\w:]+::)?(?:test|rstest|test_case)\b|@(?:Test|ParameterizedTest|TestFactory|TestTemplate)\b/.test(line)) pending = true;
      const fn = pending && (line.match(/\bfn\s+(\w+)/) || line.match(/\bvoid\s+(\w+)\s*\(/));
      if (fn) {
        out[fn[1]] = out[fn[1]] || { file, line: i + 1 };
        pending = false;
      }
    });
  }
  return out;
}

// A test's own name from the ways CI names it: "aws-crypto-mpl::test_x::it_works" -> "it_works",
// "pkg.FooTest#[x] does a thing rust-v1" -> "does a thing rust-v1".
const shortTest = name => String(name).split("::").pop().replace(/^.*?#(?:\[[^\]]*\]\s*)?/, "");

// A JUnit unique id, which a mutant's killed_by holds for a test server test:
// "[engine:junit-jupiter]/[class:a.FooTest]/[test-template:bar(...)]/[test-template-invocation:#2]"
// -> {cls: "a.FooTest", method: "bar", run: 2}. null for any other name.
function junitId(id) {
  const classes = String(id).match(/\[(?:nested-)?class:[^\]]+\]/g);
  if (!classes) return null;
  const method = String(id).match(/\[(?:method|test-template|test-factory):(\w+)/);
  const run = String(id).match(/\[(?:test-template-invocation|dynamic-test):#(\d+)\]/);
  return { cls: classes.pop().replace(/^\[(?:nested-)?class:/, "").slice(0, -1), method: method ? method[1] : null, run: run ? +run[1] : null };
}

// The shortest end of each path that no other path ends with: "src/keyring.rs" when two files are keyring.rs.
function shortPaths(paths) {
  const out = {};
  for (const p of paths) {
    const parts = p.split("/");
    let n = 1;
    const clash = end => paths.some(q => q !== p && (q === end || q.endsWith("/" + end)));
    while (n < parts.length && clash(parts.slice(-n).join("/"))) n++;
    out[p] = parts.slice(-n).join("/");
  }
  return out;
}

// The public items that added and removed lines declare. Each one is
// {file, line, side, kind, name, owner}: owner is the type of the impl block a method is in.
// A method in a builder is an option of the API that the builder builds. A test server is not a library,
// so its public items are not API.
function publicItems(file, rows, text) {
  if (!/\.rs$/.test(file) || /(^|\/)(tests?|benches|examples|test-server)\//.test(file)) return [];
  const lines = String(text || "").split("\n");
  const ownerAt = line => {
    for (let i = line - 2; i >= 0; i--) {
      const m = lines[i].match(/^impl(?:<.*?>)?\s+(?:[\w:<>, ]+\s+for\s+)?([\w:]+)/);
      if (m) return m[1].split("::").pop();
      if (/^\S/.test(lines[i]) && /^(pub\s|fn\s|struct\s|enum\s|mod\s|trait\s)/.test(lines[i])) return null;
    }
    return null;
  };
  const out = [];
  for (const row of rows) {
    if (row.kind !== "add" && row.kind !== "del") continue;
    // A use is named by its whole path, like crate::a::{B, C}.
    const m = row.text.match(/^\s*pub\s+(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?(?:(fn|struct|enum|trait|type|const|static|mod)\s+([A-Za-z_]\w*)|(use)\s+([^;]+))/);
    if (!m) continue;
    if (m[3]) { m[1] = m[3]; m[2] = m[4].trim(); }
    out.push({ file, line: row.kind === "add" ? row.new : row.old, side: row.kind === "add" ? "added" : "removed",
      kind: m[1], name: m[2], owner: m[1] === "fn" && row.kind === "add" ? ownerAt(row.new) : null });
  }
  // A method removed and added again under the same name changed its signature.
  for (const a of out.filter(x => x.side === "added")) {
    const gone = out.find(x => x.side === "removed" && x.kind === a.kind && x.name === a.name);
    if (gone) {
      a.side = "changed";
      gone.side = "changed-old";
    }
  }
  return out.filter(x => x.side !== "changed-old");
}

// What changed between two rust-api.json files: APIs added and removed, and options added, removed, or taking
// other types. Each option is {lib, api, apiName, option, takes, was}.
function apiDiff(main, pr) {
  const index = data => {
    const apis = new Map();
    for (const a of (data && data.apis) || []) apis.set(`${a.lib}|${a.id}`, a);
    return apis;
  };
  const before = index(main), after = index(pr);
  const out = { added: [], removed: [], options: { added: [], removed: [], changed: [] } };
  for (const [key, a] of after) {
    const b = before.get(key);
    if (!b) out.added.push(a);
    const old = new Map(((b && b.options) || []).map(o => [o.name, o]));
    for (const o of a.options || []) {
      const was = old.get(o.name);
      const row = { lib: a.lib, api: a.id, apiName: a.name, option: o.name, takes: o.takes, was: was ? was.takes : null, span: o.span || null };
      if (!was) out.options.added.push(row);
      else if (was.takes !== o.takes || (was.set_takes || "") !== (o.set_takes || "")) out.options.changed.push(row);
      old.delete(o.name);
    }
    if (b) for (const o of old.values()) out.options.removed.push({ lib: a.lib, api: a.id, apiName: a.name, option: o.name, takes: null, was: o.takes });
  }
  for (const [key, b] of before) if (!after.has(key)) out.removed.push(b);
  return out;
}

// The APIs and options whose code holds this line: [{lib, api, apiName, option}], option null for the type itself.
function apiAt(data, file, line) {
  const inSpan = s => s && s.file === file && s.line <= line && line <= s.end;
  const out = [];
  for (const a of (data && data.apis) || []) {
    for (const o of a.options || []) {
      if (inSpan(o.span) || inSpan(o.set_span)) out.push({ lib: a.lib, api: a.id, apiName: a.name, option: o.name });
    }
    if (inSpan(a.span)) out.push({ lib: a.lib, api: a.id, apiName: a.name, option: null });
  }
  return out;
}

// How tests ran one line: "run", "not-run", or "none" when no coverage tool counts it, like a comment.
// sources is a list of Map(file -> Map(line -> hits)).
function lineRun(sources, file, line) {
  let seen = false;
  for (const s of sources) {
    const hits = s && s.get(file) && s.get(file).get(line);
    if (hits === undefined) continue;
    if (hits > 0) return "run";
    seen = true;
  }
  return seen ? "not-run" : "none";
}

// The branches on a line that no test took, from Map(file -> Map(line -> Map(branch id -> times taken))).
function branchesMissed(branches, file, line) {
  const ids = branches && branches.get(file) && branches.get(file).get(line);
  if (!ids) return { total: 0, missed: 0 };
  let missed = 0;
  for (const t of ids.values()) if (!t) missed++;
  return { total: ids.size, missed };
}

// The things a reviewer should look at, as [{id, level, text, lines, items}]. level is "bad" for a failure
// or a gap in testing, and "note" for a change to look at, like a new API. An empty list means nothing to look at.
// files: [{filename, rows, code}]. data: what the page read (see index.html). lines lists {file, line} to jump to.
function findFlags(files, data) {
  const flags = [], add = (id, level, text, lines = [], items = []) => flags.push({ id, level, text, lines, items });
  const failed = (data.checks || []).filter(c => FAILED_CHECK.has(c.conclusion));
  if (failed.length) add("checks", "bad", `${failed.length} check${failed.length === 1 ? "" : "s"} failed`, [], failed.map(c => c.name));
  const running = (data.checks || []).filter(c => c.status !== "completed");
  if (running.length) add("running", "note", `${running.length} check${running.length === 1 ? " is" : "s are"} still running, so this list may grow`, [], running.map(c => c.name));

  const changed = [];
  for (const f of files) for (const r of f.rows) {
    if (r.kind === "add") changed.push({ file: f.filename, line: r.new, code: f.code && !TEST_FILE.test(f.filename) && !TEST_SERVER_CODE.test(f.filename) });
  }
  const coverage = [data.local, data.server].filter(Boolean);
  if (coverage.length) {
    const notRun = changed.filter(c => c.code && lineRun(coverage, c.file, c.line) === "not-run");
    if (notRun.length) add("lines", "bad", `${notRun.length} changed line${notRun.length === 1 ? "" : "s"} run in no test`, notRun);
    const partial = changed.filter(c => c.code && lineRun(coverage, c.file, c.line) === "run" && branchesMissed(data.branches, c.file, c.line).missed);
    if (partial.length) add("branches", "bad", `${partial.length} changed line${partial.length === 1 ? " has a branch" : "s have branches"} no test takes`, partial);
  } else if (changed.some(c => c.code)) {
    add("no-coverage", "note", "No line coverage on this commit yet");
  }

  if (data.mutants) {
    const bad = [];
    for (const [file, byLine] of data.mutants) for (const [line, list] of byLine) {
      if (list.some(m => BAD_MUTANT.has(m.status))) bad.push({ file, line });
    }
    const n = bad.reduce((t, b) => t + data.mutants.get(b.file).get(b.line).filter(m => BAD_MUTANT.has(m.status)).length, 0);
    if (n) add("mutants", "bad", `${n} mutant${n === 1 ? "" : "s"} no test catches`, bad);
  } else if (changed.some(c => c.code)) {
    add("no-mutants", "note", "No mutation results on this commit yet");
  }

  // data.reach has one entry per region of code under an implementation annotation; finding numbers the test annotation.
  const never = (data.reach || []).filter(r => r.state === "never-reaches");
  const findings = [...new Map(never.map(r => [r.finding, r])).values()];
  if (findings.length) add("reach", "bad", `${findings.length} duvet test${findings.length === 1 ? " never runs the code it cites" : "s never run the code they cite"}`,
    never.map(r => ({ file: r.path, line: r.from })), findings.map(r => `${r.requirement.target}: ${r.requirement.quote}`));

  const servers = (data.servers || []).filter(s => s.failed.length);
  if (servers.length) {
    const n = servers.reduce((t, s) => t + s.failed.length, 0);
    add("servers", "bad", `${n} test server case${n === 1 ? "" : "s"} failed`, [], servers.map(s => `${s.product}: ${s.failed.length}`));
  }

  const open = (data.conformance || []).filter(c => c.open.length || c.result === "FAIL");
  if (open.length) add("conformance", "bad", `Smithy conformance: ${open.reduce((t, c) => t + c.open.length, 0)} open findings`, [], open.map(c => c.crate));

  const api = data.api || {};
  const d = api.diff;
  const items = d ? [...d.added.map(a => `${a.name} added`), ...d.removed.map(a => `${a.name} removed`),
    ...d.options.added.filter(o => !d.added.some(a => a.lib === o.lib && a.id === o.api)).map(o => `${o.apiName}: ${o.option} added`),
    ...d.options.changed.map(o => `${o.apiName}: ${o.option} now takes ${o.takes}`),
    ...d.options.removed.map(o => `${o.apiName}: ${o.option} removed`)]
    : (api.items || []).map(i => `${i.owner ? i.owner + "::" : ""}${i.name} ${i.side}`);
  if (items.length) add("api", "note", d ? "The public API changes" : "Public items change", (api.items || []).map(i => ({ file: i.file, line: i.line })), items);
  return flags;
}

// Everything the page knows about one line of a file, for the side pane.
function lineEvidence(data, file, line, side = "add") {
  const at = (m, f, l) => (m && m.get(f) && m.get(f).get(l)) || [];
  const hits = s => (s && s.get(file) && s.get(file).has(line) ? s.get(file).get(line) : null);
  const tested = (data.tests ? at(data.tests.at, file, line) : []).map(i => data.tests.names[i]);
  if (side === "del") return { deleted: true, comments: at(data.comments, file, "L" + line) };
  return {
    local: hits(data.local),
    server: hits(data.server),
    branches: branchesMissed(data.branches, file, line),
    mutants: at(data.mutants, file, line),
    tests: tested,
    duvet: ((data.blocks && data.blocks.get(file)) || []).filter(b => (b.start <= line && line <= b.end) || b.code === line),
    reach: (data.reach || []).filter(r => r.path === file && r.from <= line && line <= r.to),
    api: apiAt(data.api && data.api.pr, file, line),
    comments: at(data.comments, file, "R" + line),
  };
}

const exported = { FAILED_CHECK, CODE_FILE, TEST_FILE, TEST_SERVER_CODE, BAD_MUTANT, parsePR, diffRows, annotations, testFunctions, shortTest,
  junitId, shortPaths, publicItems, apiDiff, apiAt, lineRun, branchesMissed, findFlags, lineEvidence };
if (typeof module !== "undefined") module.exports = exported;
