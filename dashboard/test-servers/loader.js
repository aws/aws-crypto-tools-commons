// Fetches everything the dashboard shows straight from GitHub, in the browser.
//
// Declarations: commons main has each product's feature catalog and server
// list; each server's feature-config.json is read from the repo and ref the
// server list names, so the page shows what CI would load.
//
// Results: the newest successful <product>-test-server.yml run on commons
// main. Its report artifact is a zip; only the JUnit TEST-*.xml entries are
// inflated and scanned. Parsed results are cached in IndexedDB by run id, so a
// reload only refetches when a newer green run exists.

const COMMONS = "aws/aws-crypto-tools-commons";
const PRODUCTS = { "ESDK":"esdk", "MPL":"mpl", "DB-ESDK":"dbesdk", "Primitives":"primitives" };

// ---------- GitHub ----------
const token = () => localStorage.getItem("github-dashboard-token") || "";

async function gh(path, accept = "application/vnd.github+json") {
  const res = await fetch("https://api.github.com/" + path, {
    headers: { Accept: accept, Authorization: "Bearer " + token() } });
  if (!res.ok) throw new Error(`GitHub ${res.status} for ${path}: ${(await res.text()).slice(0, 200)}`);
  return res;
}
const ghJson = async path => (await gh(path)).json();
const ghRaw = async (repo, path, ref) =>
  (await gh(`repos/${repo}/contents/${path}?ref=${encodeURIComponent(ref)}`, "application/vnd.github.raw")).text();
const repoSlug = url => url.match(/github\.com[:/](.+?)(?:\.git)?$/)[1];

async function fetchDeclarations(product, run) {
  const commonsRef = run.repo === COMMONS ? run.headSha : "main";
  const [catalog, servers] = await Promise.all([
    ghRaw(COMMONS, `${product}/test-server/config/feature-set.json`, commonsRef).then(JSON.parse),
    ghRaw(COMMONS, `${product}/test-server/config/server-config.json`, commonsRef).then(JSON.parse),
  ]);
  const bugList = await ghRaw(COMMONS, `${product}/test-server/config/bug-list.json`, commonsRef)
    .then(JSON.parse).catch(() => ({ bugs:{} }));
  const entries = await Promise.all(servers.entries.map(async e => {
    const repo = repoSlug(e.serverLocation.url);
    const ref = repo === run.repo ? run.headSha : e.serverLocation.ref;
    const path = `${e.configPath}/feature-config.json`, bugPath = `${e.configPath}/bug-config.json`;
    const s = { language:e.language, repo, ref, path, bugPath, supported:[], unsupported:[],
      paddings:null, bugs:[], error:null };
    try {
      const cfg = JSON.parse(await ghRaw(repo, path, ref));
      s.supported = cfg.supportedFeatures || [];
      s.unsupported = cfg.unsupportedFeatures || [];
      s.paddings = cfg.rawRsaPaddingSchemes || null;
    } catch (err) { s.error = String(err.message || err); }
    // No bug-config.json means the server declares no known bugs.
    s.bugs = await ghRaw(repo, bugPath, ref).then(JSON.parse).catch(() => []);
    return s;
  }));
  return { catalog:catalog.features, bugCatalog:bugList.bugs || {}, servers:entries };
}

const runInfo = (repo, run) => ({ repo, databaseId:run.id, headSha:run.head_sha, createdAt:run.created_at,
  url:run.html_url, branch:run.head_branch, conclusion:run.conclusion || run.status, name:run.name });

async function latestGreenRun(product) {
  const r = await ghJson(`repos/${COMMONS}/actions/workflows/${product}-test-server.yml/runs?branch=main&status=success&per_page=1`);
  return r.workflow_runs[0] && runInfo(COMMONS, r.workflow_runs[0]);
}

async function reportArtifact(repo, runId, product) {
  const arts = await ghJson(`repos/${repo}/actions/runs/${runId}/artifacts?per_page=100`);
  return arts.artifacts.filter(a => a.name === `${product}-test-server-reports` && !a.expired)
    .sort((a, b) => b.created_at.localeCompare(a.created_at))[0];
}

// Turns what the user typed into the newest finished run (passed or failed)
// that uploaded this product's reports:
//   a pull request: https://github.com/<owner>/<repo>/pull/<n>, <owner>/<repo>#<n>, or #<n> (commons)
//     -> its head commit; if nothing has finished there yet, the newest on its branch
//   a run: https://github.com/<owner>/<repo>/actions/runs/<id>, or <id> (commons)
//     -> that run if it is this product's; otherwise this product's run on the same commit
//   a commit SHA or a branch name (commons)
// Each product's TestServer is its own workflow run, so one PR or commit gives
// every product its own run.
async function resolveRun(product, text) {
  text = text.trim();
  let m, repo = COMMONS, sha = null, branch = null;
  if ((m = text.match(/github\.com\/([^/]+\/[^/]+)\/pull\/(\d+)/) || text.match(/^(?:([\w.-]+\/[\w.-]+))?#(\d+)$/))) {
    repo = m[1] || COMMONS;
    const pr = await ghJson(`repos/${repo}/pulls/${m[2]}`);
    sha = pr.head.sha; branch = pr.head.ref;
  } else if ((m = text.match(/github\.com\/([^/]+\/[^/]+)\/actions\/runs\/(\d+)/)) || /^\d+$/.test(text)) {
    repo = m ? m[1] : COMMONS;
    const run = await ghJson(`repos/${repo}/actions/runs/${m ? m[2] : text}`);
    if (await reportArtifact(repo, run.id, product)) return runInfo(repo, run);
    sha = run.head_sha;
  } else if (/^[0-9a-f]{7,40}$/i.test(text)) {
    sha = text.length === 40 ? text : (await ghJson(`repos/${repo}/commits/${text}`)).sha;
  } else {
    branch = text;
  }
  const newest = async query => {
    const runs = (await ghJson(`repos/${repo}/actions/runs?${query}&status=completed&per_page=50`)).workflow_runs;
    for (const run of runs) if (await reportArtifact(repo, run.id, product)) return runInfo(repo, run);
    return null;
  };
  const found = (sha && await newest("head_sha=" + sha)) || (branch && await newest("branch=" + encodeURIComponent(branch)));
  if (!found) throw new Error(`no finished run with ${product}-test-server-reports for "${text}" in ${repo}`);
  // Say so when the commit asked about still has runs going, or when the
  // shown run is from an older commit on the branch.
  if (sha) {
    const going = (await ghJson(`repos/${repo}/actions/runs?head_sha=${sha}&per_page=50`)).workflow_runs
      .filter(r => r.status !== "completed").length;
    if (found.headSha !== sha) found.note = `older commit: ${sha.slice(0, 7)} has no finished run yet`;
    else if (going) found.note = `${going} run${going > 1 ? "s" : ""} still going on this commit`;
  }
  return found;
}

// ---------- cache ----------
function idb() {
  return new Promise((ok, bad) => {
    const req = indexedDB.open("test-server-dashboard", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("results");
    req.onsuccess = () => ok(req.result);
    req.onerror = () => bad(req.error);
  });
}
async function cacheGet(key) {
  const db = await idb();
  return new Promise(ok => { const q = db.transaction("results").objectStore("results").get(key); q.onsuccess = () => ok(q.result); q.onerror = () => ok(undefined); });
}
async function cachePut(key, value) {
  const db = await idb();
  return new Promise(ok => { const t = db.transaction("results", "readwrite"); t.objectStore("results").put(value, key); t.oncomplete = ok; t.onerror = ok; });
}

// ---------- zip ----------
// Reads the central directory, then inflates the wanted entries one at a time
// as text streams. Report zips are far below 4 GB, so zip64 is not handled.
function zipEntries(buf) {
  const v = new DataView(buf);
  let eocd = -1;
  for (let i = buf.byteLength - 22; i >= Math.max(0, buf.byteLength - 65557); i--)
    if (v.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error("not a zip file");
  const count = v.getUint16(eocd + 10, true);
  let p = v.getUint32(eocd + 16, true);
  const dec = new TextDecoder(), out = [];
  for (let i = 0; i < count; i++) {
    const method = v.getUint16(p + 10, true), csize = v.getUint32(p + 20, true);
    const nlen = v.getUint16(p + 28, true), xlen = v.getUint16(p + 30, true), clen = v.getUint16(p + 32, true);
    const local = v.getUint32(p + 42, true);
    const name = dec.decode(new Uint8Array(buf, p + 46, nlen));
    out.push({ name, method, csize, local });
    p += 46 + nlen + xlen + clen;
  }
  return out;
}
function entryStream(buf, e) {
  const v = new DataView(buf);
  const start = e.local + 30 + v.getUint16(e.local + 26, true) + v.getUint16(e.local + 28, true);
  let s = new Blob([new Uint8Array(buf, start, e.csize)]).stream();
  if (e.method === 8) s = s.pipeThrough(new DecompressionStream("deflate-raw"));
  else if (e.method !== 0) throw new Error(`zip method ${e.method} not supported for ${e.name}`);
  return s.pipeThrough(new TextDecoderStream());
}

// ---------- JUnit ----------
// One target label ("rust-v1") or a pair ("java-v3->rust-v1") ends each name.
// Decrypt-side tests against a reference encryptor prefix the pair with "ref:".
const TARGETS = /\s+(?:ref:)?([a-z][a-z-]*?-v\d+)(?:->([a-z][a-z-]*?-v\d+))?$/;
const LABEL = /[a-z][a-z-]*?-v\d+/g;
const FEATURE = /feature=([^\s,\]]+)/g;
const TESTCASE = /<testcase\b([^>]*?)(?:\/>|>([\s\S]*?)<\/testcase>)/g;
const unxml = s => s.replace(/&(lt|gt|amp|quot|apos|#\d+|#x[0-9a-f]+);/gi, (_, e) =>
  ({ lt:"<", gt:">", amp:"&", quot:'"', apos:"'" })[e] ?? String.fromCodePoint(e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : +e.slice(1)));
const attr = (s, n) => { const m = s.match(new RegExp(`\\b${n}="([^"]*)"`)); return m ? unxml(m[1]) : null; };
const langOf = l => l.replace(/-v\d+$/, "");
const featuresIn = msg => [...msg.split("unsupported by")[0].matchAll(FEATURE)].map(m => m[1]);

function reasonOf(msg) {
  if (msg.startsWith("feature-gated skip")) return "feature-gated: " + featuresIn(msg).join(", ");
  const bug = msg.match(/^KNOWN BUG (\S+?)(?::|\s|$)/);
  if (bug) return "KNOWN BUG " + bug[1];
  if (msg.startsWith("padding-gated skip")) return "padding-gated: " + [...msg.matchAll(/rawRsaPadding=(\S+)/g)].map(m => m[1]).join(", ");
  // Drop what varies per run (server labels, pairs, counts) so one cause is one row.
  return msg.replace(/^Assumption failed: /, "")
    .replace(/\s*\([^)]*-v\d+[^)]*\)/g, "")
    .replace(/^\d+ \S+ (raw RSA )?vectors/, "$1vectors")
    .replace(LABEL, "this server")
    .replace(/\[[^\]]*\]/g, "[…]").slice(0, 160);
}

// The gate log (feature-gate-log.jsonl, written by FeatureGateLog in
// commons tests-support): one line per FeatureGate.require call. Keyed by
// test class + display name, which is how the JUnit XML names a test run.
async function readGateLog(stream) {
  const log = new Map();
  let buf = "";
  const reader = stream.getReader();
  const take = line => {
    if (!line) return;
    const d = JSON.parse(line), cls = d.id.match(/\[class:([^\]]+)\]/);
    if (!cls) return;
    const k = cls[1] + "\u0000" + d.name;
    if (!log.has(k)) log.set(k, []);
    log.get(k).push({ t:d.targets, f:d.features });
  };
  for (;;) {
    const { value, done } = await reader.read();
    if (value) buf += value;
    const lines = buf.split("\n");
    buf = done ? "" : lines.pop();
    lines.forEach(take);
    if (done) { take(buf); return log; }
  }
}

// Counts per language: [pass, fail, gate skip, partner skip, other skip].
// "gate skip": the feature gate skipped it for this language's own
// unsupported feature (expected). "partner skip": the skip names only the
// other target in the pair. "other skip": known bug, padding gate, etc.
//
// With a gate log, the same counts are also kept per language per feature
// set (lf), where the feature set is what the gate required of THAT
// language in THAT run. An encryptor and a decryptor in one run can need
// different features, so this is what a feature x server cell must count.
function addTestcase(cases, attrs, body, gateLog) {
  const fqcn = attr(attrs, "classname"), name = attr(attrs, "name"), cls = fqcn.split(".").pop();
  const m = name.match(TARGETS);
  const caseName = m ? name.slice(0, m.index) : name;
  const labels = m ? [m[1], m[2]].filter(Boolean) : [];
  const vec = caseName.match(/^[0-9a-f-]{36} \((.*)\)$/);
  const method = vec ? vec[1] : caseName.split(/[\s[(/]/)[0];
  const key = cls + "\u0000" + caseName;
  let c = cases.get(key);
  if (!c) cases.set(key, c = { c:cls, m:method, n:caseName, pair:labels.length === 2, f:new Set(), langs:{}, pairs:{}, why:{}, err:{}, lf:null, logged:false });
  const calls = gateLog && gateLog.get(fqcn + "\u0000" + name);
  if (calls) c.logged = true;
  const sk = body && body.match(/<skipped\b([^>]*)/), fl = body && body.match(/<(?:failure|error)\b([^>]*)/);
  const status = sk ? 2 : fl ? 1 : 0;
  const msg = sk ? attr(sk[1], "message") || "" : "";
  const blamed = new Set(msg.match(LABEL) || []);
  const gated = msg.startsWith("feature-gated");
  if (gated) featuresIn(msg).forEach(f => c.f.add(f));
  for (const lab of labels.length ? labels : ["(none)"]) {
    const l = langOf(lab), r = c.langs[l] ??= [0, 0, 0, 0, 0];
    const idx = status !== 2 ? status : blamed.size && !blamed.has(lab) ? 3 : gated ? 2 : 4;
    r[idx]++;
    if (gateLog) {
      const feats = new Set();
      for (const call of calls || []) if (call.t.includes(lab)) call.f.forEach(f => feats.add(f));
      feats.forEach(f => c.f.add(f));
      // Key: role (E encryptor, D decryptor, S single server) | feature set.
      const role = labels.length === 2 ? (lab === labels[0] && labels[0] !== labels[1] ? "E" : lab === labels[1] && labels[0] !== labels[1] ? "D" : "S") : "S";
      const fk = role + "|" + [...feats].sort().join("+");
      ((c.lf ??= {})[l] ??= {})[fk] ??= [0, 0, 0, 0, 0];
      c.lf[l][fk][idx]++;
    }
  }
  // Per encryptor>decryptor pair: [pass, fail, gate skip, other skip].
  if (labels.length === 2) {
    const p = c.pairs[langOf(labels[0]) + ">" + langOf(labels[1])] ??= [0, 0, 0, 0];
    p[status !== 2 ? status : gated ? 2 : 3]++;
  }
  // why: skip reason -> language -> runs. A reason is charged to the
  // languages its message names; a message naming none is charged to all.
  if (sk) {
    const w = c.why[reasonOf(msg)] ??= {};
    // A summary skip with no target in its name is charged to the servers it names.
    // "decryptor ..." and "encryptor ..." assumptions are about one side of the pair.
    const side = labels.length === 2 && /^(Assumption failed: )?(en|de)cryptor\b/.exec(msg);
    const charged = side ? [labels[side[2] === "en" ? 0 : 1]]
      : labels.length ? labels.filter(l => !blamed.size || blamed.has(l)) : [...blamed];
    for (const l of charged) w[langOf(l)] = (w[langOf(l)] || 0) + 1;
  }
  if (fl) {
    const fmsg = attr(fl[1], "message") || "";
    labels.forEach(l => c.err[langOf(l)] ??= fmsg.slice(0, 400));
    // KnownBugGate fails a run whose declared bug no longer reproduces.
    const stale = fmsg.match(/known bug did not reproduce — remove '([^']+)' for (\S+)/);
    if (stale) (c.stale ??= {})[stale[1]] = langOf(stale[2].replace(/[^a-z0-9-]+$/i, ""));
  }
}

async function scanXml(stream, cases, gateLog) {
  let buf = "";
  const reader = stream.getReader();
  for (;;) {
    const { value, done } = await reader.read();
    if (value) buf += value;
    TESTCASE.lastIndex = 0;
    let m, end = 0;
    while ((m = TESTCASE.exec(buf))) { addTestcase(cases, m[1], m[2], gateLog); end = TESTCASE.lastIndex; }
    buf = buf.slice(end);
    if (done) return;
  }
}

async function fetchResults(product, run, progress) {
  // Bump the prefix when the stored shape changes, so old caches are ignored.
  const key = `v4:${run.repo}:${product}:${run.databaseId}`;
  const hit = await cacheGet(key);
  if (hit) return hit;
  const art = await reportArtifact(run.repo, run.databaseId, product);
  if (!art) throw new Error(`run ${run.databaseId} has no ${product}-test-server-reports artifact`);
  progress(`Downloading ${product} reports (${(art.size_in_bytes / 1e6).toFixed(1)} MB)…`);
  const zip = await (await gh(`repos/${run.repo}/actions/artifacts/${art.id}/zip`)).arrayBuffer();
  const entries = zipEntries(zip);
  const xmls = entries.filter(e => /test-results\/.*TEST-[^/]*\.xml$/.test(e.name));
  const logEntry = entries.find(e => /test-results\/feature-gate-log\.jsonl$/.test(e.name));
  let gateLog = null;
  if (logEntry) {
    progress(`Reading ${product} feature-gate log…`);
    gateLog = await readGateLog(entryStream(zip, logEntry));
  }
  const cases = new Map();
  for (const [i, e] of xmls.entries()) {
    progress(`Reading ${product} results ${i + 1}/${xmls.length}: ${e.name.split("/").pop()}`);
    await scanXml(entryStream(zip, e), cases, gateLog);
  }
  const langs = [...new Set([...cases.values()].flatMap(c => Object.keys(c.langs)))].sort();
  // src: "log" = features from the gate log; "g" = only from gate skip
  // messages (a run without the log); "" = the test never called the gate.
  const out = [...cases.values()].sort((a, b) => a.c.localeCompare(b.c) || a.n.localeCompare(b.n)).map(c => ({
    c:c.c, m:c.m, n:c.n, pair:c.pair, f:[...c.f].sort(),
    src: c.logged ? "log" : !gateLog && c.f.size ? "g" : "",
    r: langs.map(l => c.langs[l] || [0, 0, 0, 0, 0]), p:c.pairs, lf:c.lf,
    why:c.why, err:c.err, stale:c.stale }));
  const result = { run, langs, cases:out, gateLog:!!gateLog };
  await cachePut(key, result);
  return result;
}

// ---------- line coverage ----------
// A test server run's report zip holds coverage/<language>.lcov (paths
// relative to the library's repository) and coverage/<language>.json, which
// names that repository and commit. The repository's own CI uploads its local
// test coverage as local-coverage-<project> artifacts, each one lcov file.

// lcov text -> Map(file -> Map(line -> hits)). Only DA (line) records count.
function parseLcov(text, into = new Map()) {
  let lines = null;
  for (const row of text.split("\n")) {
    if (row.startsWith("SF:")) {
      const f = row.slice(3).trim();
      lines = into.get(f) || new Map();
      into.set(f, lines);
    } else if (lines && row.startsWith("DA:")) {
      const [n, hits] = row.slice(3).split(",");
      lines.set(+n, Math.max(lines.get(+n) || 0, +hits));
    } else if (row.startsWith("end_of_record")) lines = null;
  }
  return into;
}

async function zipText(zip, e) {
  let text = "";
  const reader = entryStream(zip, e).getReader();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return text;
    text += value;
  }
}

// Local coverage for a commit: the given run's own artifacts first (a test
// server run inside the library's CI), else the newest run on that commit.
async function localCoverage(repo, commit, run, progress) {
  const named = async runId => (await ghJson(`repos/${repo}/actions/runs/${runId}/artifacts?per_page=100`))
    .artifacts.filter(a => a.name.startsWith("local-coverage-") && !a.expired);
  let arts = run.repo === repo ? await named(run.databaseId) : [];
  let from = arts.length ? run.url : null;
  if (!arts.length) {
    const runs = (await ghJson(`repos/${repo}/actions/runs?head_sha=${commit}&per_page=30`)).workflow_runs;
    for (const r of runs) { arts = await named(r.id); if (arts.length) { from = r.html_url; break; } }
  }
  if (!arts.length) return null;
  const files = new Map();
  for (const a of arts) {
    progress(`Downloading ${a.name}…`);
    const zip = await (await gh(`repos/${repo}/actions/artifacts/${a.id}/zip`)).arrayBuffer();
    for (const e of zipEntries(zip).filter(e => e.name.endsWith(".lcov"))) parseLcov(await zipText(zip, e), files);
  }
  return { files, from, artifacts:arts.map(a => a.name) };
}

// -> [{ language, repository, commit, server: Map, local: {files, from} | null }]
async function fetchCoverage(product, run, progress) {
  const key = `cov1:${run.repo}:${product}:${run.databaseId}`;
  const hit = await cacheGet(key);
  if (hit) return hit;
  const art = await reportArtifact(run.repo, run.databaseId, product);
  if (!art) throw new Error(`run ${run.databaseId} has no ${product}-test-server-reports artifact`);
  progress(`Downloading ${product} reports (${(art.size_in_bytes / 1e6).toFixed(1)} MB)…`);
  const zip = await (await gh(`repos/${run.repo}/actions/artifacts/${art.id}/zip`)).arrayBuffer();
  const entries = zipEntries(zip);
  const out = [];
  for (const e of entries.filter(e => /(^|\/)coverage\/[^/]+\.json$/.test(e.name))) {
    const meta = JSON.parse(await zipText(zip, e));
    const lcov = entries.find(x => x.name === e.name.replace(/\.json$/, ".lcov"));
    if (!lcov) continue;
    progress(`Reading ${meta.language} coverage…`);
    const server = parseLcov(await zipText(zip, lcov));
    progress(`Finding ${meta.repository} local coverage for ${meta.commit.slice(0, 7)}…`);
    const local = await localCoverage(meta.repository, meta.commit, run, progress);
    out.push({ ...meta, server, local });
  }
  // Only cache a finished answer: local coverage may still be on its way.
  if (out.every(c => c.local)) await cachePut(key, out);
  return out;
}

// source: "" for the newest green run on commons main, else anything resolveRun takes.
async function loadProduct(label, progress, source = "") {
  const product = PRODUCTS[label];
  progress(`Finding the ${label} run…`);
  const run = source ? await resolveRun(product, source) : await latestGreenRun(product);
  if (!run) throw new Error(`no successful ${product}-test-server.yml run on main`);
  progress(`Reading ${label} declarations…`);
  // A server built from the run's own repo is read at the run's commit, so a
  // feature-config.json change on a branch shows up with that branch's run.
  const decl = await fetchDeclarations(product, run);
  const results = await fetchResults(product, run, progress);
  return { decl, results };
}
