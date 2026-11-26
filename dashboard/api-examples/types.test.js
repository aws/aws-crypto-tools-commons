// Run with: node --test dashboard/api-examples/types.test.js
// Runs the script in types.html against stand-ins for the page's elements and data files.
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const SCRIPT = fs.readFileSync(path.join(__dirname, "types.html"), "utf8").split("<script>")[1].split("</script>")[0];
const ROOT = path.join(__dirname, "..", "..");
const committed = name => JSON.parse(fs.readFileSync(path.join(__dirname, name), "utf8"));
const unesc = s => s.replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");

const ROW = (type, calls, code, kind, more = {}) => ({ type, calls, code, kind, ...more });
const TYPES = {
  note: "Rust note.",
  others_note: "Others note.",
  rust_commit: "e77da7789ee19d516e44d4b4b389942290b7a0b2",
  rustc: "1.99.1",
  files: { trials: "api-examples/types/rust_trials.rs", runs: "api-examples/types/rust_runs.rs", check: ".github/workflows/api-examples-types.yml" },
  apis: [
    { name: "Raw AES keyring", call: "RawAesKeyring::builder()", options: ["mpl/RawAesKeyring.wrapping_key"] },
    { name: "encrypt", call: "client", options: ["esdk/encrypt.plaintext"] },
    { name: "decrypt", call: "client", options: ["esdk/decrypt.ciphertext"] },
  ],
  takes: { "mpl/RawAesKeyring.wrapping_key": "impl Into<Blob>", "esdk/encrypt.plaintext": "&[u8]", "esdk/decrypt.ciphertext": "&[u8]" },
  shipped: { "mpl/RawAesKeyring.wrapping_key": { java: ["ByteBuffer"] }, "esdk/encrypt.plaintext": { java: ["byte[]", "String"] } },
  usage_keys: { "esdk/encrypt.plaintext": ["esdk|encrypt", "plaintext"] },
  rust: {
    "mpl/RawAesKeyring.wrapping_key": [
      ROW("Vec<u8>", 0, ".wrapping_key(x)", "bytes", { trial: 5, test: 6, run: { builds: true, same: true } }),
      ROW("&str", 0, ".wrapping_key(x)", "text", { trial: 6, test: 16, run: { builds: true, same: true } }),
    ],
    "esdk/encrypt.plaintext": [
      ROW("&[u8]", 0, ".encrypt().plaintext(x)", "bytes", { trial: 10, test: 20, run: { builds: true, same: true, copies: false } }),
      ROW("[u8; 32]", 0, ".encrypt().plaintext(&x)", "bytes", { trial: 11, test: 30, run: { skipped: "the value is not 32 bytes" } }),
      ROW("String", 1, ".encrypt().plaintext(x.as_bytes())", "text", { trial: 12, test: 40, run: { builds: true, same: true, copies: true } }),
      ROW("PathBuf", 2, ".encrypt().plaintext(&std::fs::read(x).unwrap())", "path", { trial: 13, test: 50, run: { builds: true, same: false } }),
      ROW("char", null, "", "text", { trial: null }),
    ],
    "esdk/decrypt.ciphertext": [
      ROW("&[u8]", 0, ".decrypt().ciphertext(x)", "bytes", { trial: 20, test: 60, run: { builds: true, same: true, copies: false } }),
      ROW("String", 1, ".decrypt().ciphertext(x.as_bytes())", "text",
        { trial: 21, test: 70, run: { builds: false, error: "Serialization(SerializationError { message: \"input appears to be Base64-encoded\" })" } }),
    ],
  },
  others: {
    "mpl/RawAesKeyring.wrapping_key": { java: [ROW("String", 1, "ByteBuffer.wrap(x.getBytes())", "text")] },
    "esdk/encrypt.plaintext": {
      java: [ROW("byte[]", 0, "crypto.encryptData(keyring, x)", "bytes"), ROW("String", 0, "crypto.encryptString(provider, x, context)", "text")],
    },
  },
};

const RULES = { rules: {
  "mpl/RawAesKeyring.wrapping_key": { refuse: ["text", "optional text"], why: "Text is not a key." },
  "esdk/decrypt.ciphertext": { refuse: ["text", "optional text"], why: "Ciphertext text is base64." },
} };

const HIT = (repo, file, line, code, source, more = {}) => ({ repo, path: file, line, language: "python",
  url: `https://github.com/${repo}/blob/c0ffee/${file}#L${line}`, code, assignment: null, blob: null, aws_copy: false, source, ...more });
const USAGE = {
  generated_at: "2026-11-25T22:07:40Z",
  languages: { python: { files: 5, repos: 4, calls: 6 } },
  search: { skipped: ["forks", "private repos"], sources: "Hits in one file count as one source." },
  apis: { "esdk|encrypt": { plaintext: [{
    conversion: ".encode()", from: "a string", count: 5, languages: { python: 5 }, examples: [], repos: 4, sources: 3, aws_copies: 1,
    hits: [
      HIT("acme/one", "app/main.py", 10, "client.encrypt(source=data.encode())", 0),
      HIT("acme/one", "app/main.py", 20, "client.encrypt(source=text.encode())", 0),
      HIT("acme/two", "a/b/crypto.py", 5, "client.encrypt(source=body.encode())", 1),
      HIT("acme/three", "c/b/crypto.py", 5, "client.encrypt(source=body.encode())", 1),
      HIT("acme/four", "run.py", 3, "client.encrypt(source=x)", 2, { assignment: "x = raw.encode()" }),
      HIT("acme/five", "aws_lambda_powertools/kms.py", 7, "client.encrypt(source=y.encode())", undefined, { aws_copy: true }),
    ],
  }] } },
};

const PROPOSALS = {
  checked: "Proposals: compiled.",
  options: { "esdk/encrypt.plaintext": { why: "Takes text too.", languages: { rust: {
    signature: "plaintext(impl Into<Plaintext>)",
    breaks: [".encrypt().plaintext(x.as_ref()) with Vec<u8>"],
    rows: [ROW("&[u8]", 0, ".encrypt().plaintext(x)", "bytes", { today: 0 }), ROW("String", 0, ".encrypt().plaintext(&x)", "text", { today: 1, proposed: true })],
  } } } },
};

// Opens the page with these data files. A file that is null fails to load.
async function open(files = {}, search = "") {
  const all = { "types.json": TYPES, "usage.json": USAGE, "expectations.json": RULES, "proposals.json": null, ...files };
  const els = {};
  const document = {
    getElementById: id => els[id] || (els[id] = { innerHTML: "", textContent: "", on: {}, classList: { add() {}, remove() {} },
      style: { setProperty() {} }, addEventListener(type, f) { this.on[type] = f; } }),
    querySelectorAll: () => [],
  };
  const fetch = async name => ({ ok: all[name] !== null, json: async () => structuredClone(all[name]) });
  const localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
  new Function("document", "fetch", "location", "localStorage", SCRIPT)(document, fetch, { search }, localStorage);
  await new Promise(resolve => setTimeout(resolve, 20));
  // A click on an element in #id that matches each selector in `matches`, with that selector's dataset.
  const click = (id, matches) => els[id].on.click({ target: { closest: s => (s in matches ? { dataset: matches[s], classList: { add() {} } } : null) } });
  const data = all["types.json"];
  return {
    els,
    pickApi: key => click("apis", { button: { api: String(data.apis.findIndex(a => a.options.includes(key))) } }),
    pickLang: lang => click("langs", { button: { lang } }),
    chip: (key, lang, type) => {
      click("view", { ".chip": { key, lang, type } });
      return els.detail.innerHTML;
    },
    openRow: id => click("view", { "tr[data-open]": { open: id } }),
    cust: id => click("view", { ".cust": { cust: id } }),
    propose: key => click("view", { ".prop": { prop: key } }),
  };
}

// The chips in some HTML, as {type: the chip's HTML}.
const chips = html => Object.fromEntries([...html.matchAll(/<span class="chip[^"]*"[^>]*data-type="([^"]*)">.*?<\/span>/g)].map(m => [unesc(m[1]), m[0]]));

// The column title above each type in one option's row of the map.
function columns(html, option) {
  const titles = [...html.matchAll(/<th>(.*?)<\/th>/g)].map(m => unesc(m[1])).slice(1);
  const row = html.split("<tr>").find(r => r.includes(`<b>${option}</b>`));
  const out = {};
  row.split("<td").slice(2).forEach((cell, i) => {
    for (const type of Object.keys(chips(cell))) out[type] = titles[i];
  });
  return out;
}

test("each type sits under its number of calls", async () => {
  const page = await open();
  page.pickApi("esdk/encrypt.plaintext");
  assert.deepStrictEqual(columns(page.els.view.innerHTML, "plaintext"),
    { "&[u8]": "As is", "[u8; 32]": "As is", String: "One call", PathBuf: ">1 call", char: "No fix found" });
});

test("a rule marks an option that takes refused text as is", async () => {
  const page = await open();
  const map = chips(page.els.view.innerHTML);
  assert.match(map["&str"], /class="chip b0 warn"/);
  assert.match(map["&str"], /&amp;str ⚠/);
  assert.doesNotMatch(map["Vec<u8>"], /warn/);
  assert.match(page.chip("mpl/RawAesKeyring.wrapping_key", "rust", "&str"), /⚠ Rule: Takes text as is, which the rule refuses\. Text is not a key\./);
  page.pickLang("java");
  assert.match(page.chip("mpl/RawAesKeyring.wrapping_key", "java", "String"), /✅ Rule: Needs a conversion, as the rule asks\./);
  page.pickLang("rust");
  page.pickApi("esdk/encrypt.plaintext");
  assert.doesNotMatch(chips(page.els.view.innerHTML).String, /warn/);
  assert.doesNotMatch(page.chip("esdk/encrypt.plaintext", "rust", "String"), /Rule:/);
});

test("a Rust chip shows its call, links the trial that compiled and its test, and links CI", async () => {
  const page = await open();
  page.pickApi("esdk/encrypt.plaintext");
  const panel = page.chip("esdk/encrypt.plaintext", "rust", "String");
  assert.match(panel, /<pre>client\.encrypt\(\)\.plaintext\(x\.as_bytes\(\)\)<\/pre>/);
  assert.match(panel, /one call: 1 call\./);
  const links = [...panel.matchAll(/href="([^"]*)"/g)].map(m => m[1]);
  assert.deepStrictEqual(links, [
    "https://github.com/aws/aws-crypto-tools-commons/blob/main/api-examples/types/rust_trials.rs#L12",
    "https://github.com/aws/aws-crypto-tools-commons/blob/main/api-examples/types/rust_runs.rs#L40",
    "https://github.com/aws/aws-crypto-tools-commons/actions/workflows/api-examples-types.yml?query=branch%3Amain",
    "https://github.com/aws/aws-crypto-tools-rust/tree/e77da7789ee19d516e44d4b4b389942290b7a0b2",
  ]);
  assert.match(panel, /<\/a> with rustc 1\.99\.1\.<\/li>/);
  assert.match(page.chip("esdk/encrypt.plaintext", "rust", "char"), /<pre>No fix in the list works\.<\/pre>.*❌ No fix in the list compiled\./);
});

test("links go to the branch that ?ref names", async () => {
  const page = await open({}, "?ref=lucmcdon/api-examples");
  const panel = page.chip("mpl/RawAesKeyring.wrapping_key", "rust", "Vec<u8>");
  assert.match(panel, /blob\/lucmcdon\/api-examples\/api-examples\/types\/rust_trials\.rs#L5"/);
  assert.match(panel, /query=branch%3Alucmcdon%2Fapi-examples"/);
});

test("the panel says what the run found, and a failed run strikes its chip", async () => {
  const page = await open();
  page.pickApi("esdk/encrypt.plaintext");
  const ran = type => page.chip("esdk/encrypt.plaintext", "rust", type).match(/<li>([^<]*Ran[^<]*|⏭[^<]*)/)[1];
  assert.strictEqual(ran("&[u8]"), "✅ Ran: it works, and gives the same result as the reference value. Passing the value doesn't copy it. ");
  assert.strictEqual(ran("String"), "✅ Ran: it works, and gives the same result as the reference value. Passing the value copies it. ");
  assert.strictEqual(ran("PathBuf"), "❌ Ran: it works, but the result differs from the reference value. ");
  assert.strictEqual(ran("[u8; 32]"), "⏭ Not run: the value is not 32 bytes. ");
  const map = chips(page.els.view.innerHTML);
  assert.match(map.PathBuf, /failed.*✗/);
  assert.doesNotMatch(map["[u8; 32]"], /failed/);
  page.pickApi("esdk/decrypt.ciphertext");
  assert.match(chips(page.els.view.innerHTML).String, /class="chip b1 failed".*String ✗/);
  assert.match(page.chip("esdk/decrypt.ciphertext", "rust", "String"),
    /❌ Ran: it failed with Serialization\(SerializationError \{ message: &quot;input appears to be Base64-encoded&quot; \}\)\./);
});

test("another language's chip shows its own code and says it is not compiled", async () => {
  const page = await open();
  page.pickApi("esdk/encrypt.plaintext");
  page.pickLang("java");
  assert.deepStrictEqual(Object.keys(chips(page.els.view.innerHTML)), ["byte[]", "String"]);
  const panel = page.chip("esdk/encrypt.plaintext", "java", "String");
  assert.match(panel, /<pre>crypto\.encryptString\(provider, x, context\)<\/pre>/);
  assert.match(panel, /Not compiled or run\./);
  assert.doesNotMatch(panel, /rust_trials/);
});

test("a comparison row shows each language's cheapest type, and opens to list them all", async () => {
  const page = await open();
  page.pickApi("esdk/encrypt.plaintext");
  page.pickLang("compare");
  const row = kind => page.els.view.innerHTML.split("<tr").find(r => r.includes(`data-open="esdk/encrypt.plaintext|${kind}"`));
  assert.match(row("bytes"), /<td class="kind">▸ bytes<\/td><td class="ck"><span class="chip b0"[^>]*>as is<\/span><small>&amp;\[u8\] \+1<\/small>/);
  assert.doesNotMatch(page.els.view.innerHTML, /class="detail"/);
  page.openRow("esdk/encrypt.plaintext|bytes");
  const detail = page.els.view.innerHTML.split('<tr class="detail">')[1].split("</tr>")[0];
  assert.deepStrictEqual(Object.keys(chips(detail)), ["&[u8]", "[u8; 32]", "byte[]"]);
  assert.match(row("bytes"), /▾ bytes/);
});

test("a customer cell counts the sources that had that kind of value, and opens every hit, grouped by source", async () => {
  const page = await open();
  page.pickApi("esdk/encrypt.plaintext");
  page.pickLang("compare");
  const row = page.els.view.innerHTML.split("<tr").find(r => r.includes('data-open="esdk/encrypt.plaintext|text"'));
  assert.match(row, /<span class="cust" data-cust="esdk\/encrypt.plaintext\|text"[^>]*>3 sources<\/span>/);
  assert.doesNotMatch(page.els.view.innerHTML, /\.encode\(\)/, "the table names no calls");
  page.cust("esdk/encrypt.plaintext|text");
  const pane = page.els.detail.innerHTML;
  assert.match(pane, /Customers who have text, and convert it before the call · 3 sources · 5 hits/);
  assert.match(pane, /<code>\.encode\(\)<\/code> <span class="ev">from a string · 3 sources · 5 hits in 4 repos \(python 5\), plus 1 in copies of AWS code<\/span>/);
  const [counted, aws] = pane.split("Copies of AWS code, not counted:");
  const links = text => [...text.matchAll(/<a href="([^"]*)"/g)].map(m => m[1]);
  assert.deepStrictEqual(links(counted.split('<div class="hits">')[1]), USAGE.apis["esdk|encrypt"].plaintext[0].hits.slice(0, 5).map(h => h.url));
  assert.deepStrictEqual(links(aws.split("</details>")[0]), ["https://github.com/acme/five/blob/c0ffee/aws_lambda_powertools/kms.py#L7"]);
  const sources = counted.split('<div class="source">').slice(1);
  assert.strictEqual(sources.length, 3);
  assert.match(sources[0], /^<span class="tag">2 calls in one file<\/span>.*data\.encode.*text\.encode/);
  assert.match(sources[1], /^<span class="tag">2 copies<\/span>/);
  assert.strictEqual(sources[1].match(/<code>/g).length, 1, "a line in several copies shows once");
  assert.match(sources[2], /^<div><code>client\.encrypt\(source=x\)<\/code><br><code>x = raw\.encode\(\)<\/code>/);
});

test("the footer says how the customer search ran", async () => {
  const page = await open();
  const foot = page.els.foot.textContent;
  assert.match(foot, /GitHub code search on 2026-11-25T22:07:40Z, 6 calls\. Skipped: forks; private repos\. Hits in one file count as one source\./);
  const without = await open({ "usage.json": null });
  without.pickApi("esdk/encrypt.plaintext");
  without.pickLang("compare");
  assert.match(without.els.view.innerHTML, /usage\.json didn't load, so customer counts are hidden/);
});

test("a proposal moves the types it makes cheaper, and the panel says what it was", async () => {
  const page = await open({ "proposals.json": PROPOSALS });
  page.pickApi("esdk/encrypt.plaintext");
  assert.doesNotMatch(page.els.view.innerHTML, /▲/);
  page.propose("esdk/encrypt.plaintext");
  const html = page.els.view.innerHTML;
  assert.deepStrictEqual(columns(html, "plaintext"), { "&[u8]": "As is", String: "As is" });
  assert.match(chips(html).String, /String ▲/);
  assert.doesNotMatch(chips(html)["&[u8]"], /▲|▼/);
  assert.match(html, /Breaks \.encrypt\(\)\.plaintext\(x\.as_ref\(\)\) with Vec&lt;u8&gt;/);
  assert.match(page.chip("esdk/encrypt.plaintext", "rust", "String"),
    /✏️ Proposed: <code>plaintext\(impl Into&lt;Plaintext&gt;\)<\/code>\. Compiled against a model of it, not run\. Today: one call\./);
  page.propose("esdk/encrypt.plaintext");
  assert.strictEqual(columns(page.els.view.innerHTML, "plaintext").String, "One call");
});

// The tests below read the committed data files.

test("every chip on the committed page opens its panel", async () => {
  const types = committed("types.json");
  const page = await open({ "types.json": types, "usage.json": committed("usage.json"), "expectations.json": committed("expectations.json") });
  let opened = 0;
  for (const api of types.apis) {
    page.pickApi(api.options[0]);
    for (const lang of ["rust", "java", "python", "dotnet", "go", "javascript", "compare"]) {
      page.pickLang(lang);
      for (const m of page.els.view.innerHTML.matchAll(/data-key="([^"]*)" data-lang="([^"]*)" data-type="([^"]*)"/g)) {
        assert.match(page.chip(unesc(m[1]), m[2], unesc(m[3])), /<h2>/);
        opened++;
      }
    }
  }
  // The Rust map alone has a chip for each Rust row.
  const rustRows = Object.values(types.rust).reduce((n, rows) => n + rows.length, 0);
  assert.ok(opened > rustRows, `opened ${opened} chips for ${rustRows} Rust rows`);
});

test("each committed Rust row's links land on its trial and its test", () => {
  const types = committed("types.json");
  const trials = fs.readFileSync(path.join(ROOT, types.files.trials), "utf8").split("\n");
  const runs = fs.readFileSync(path.join(ROOT, types.files.runs), "utf8").split("\n");
  let checked = 0;
  for (const [key, rows] of Object.entries(types.rust)) {
    for (const row of rows.filter(r => r.trial)) {
      // The trial's call has full paths, and the row's call is how the page shows it.
      assert.ok(trials[row.trial - 1].endsWith(` // ${key}: ${row.type}`), `${key} ${row.type}: ${trials[row.trial - 1]}`);
      const call = trials[row.trial - 1].split("let _ = ")[1].split("; }")[0];
      assert.ok(call.replace(/\b(?:aws_crypto_mpl|aws_esdk)::(?:[a-z_]\w*::)*/g, "").endsWith(row.code), `${key} ${row.type}: ${call}`);
      checked++;
      // Only some options have run tests.
      if (!row.test) continue;
      assert.match(runs[row.test - 1], /^async fn run_\d+\(\) \{$/);
      assert.strictEqual(runs[row.test], `    // ${key}: ${row.type} passed as ${row.code}`);
    }
  }
  assert.ok(checked > 100, `checked ${checked} rows`);
});
