// Run with: node --test dashboard/api-examples/types.test.js
// Runs the script in types.html against stand-ins for the page's elements and data files. With no GitHub token,
// the page reads the committed files, which these tests replace.
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
const WRAP = "mpl|raw-aes-keyring|wrappingKey", PLAIN = "esdk|encrypt|plaintext", KEYRING = "esdk|encrypt|keyring",
  CIPHER = "esdk|decrypt|ciphertext", RSA = "mpl|raw-rsa-keyring|publicKey", CMM_KEYRING = "mpl|default-cmm|keyring";
const RUST = {
  note: "Rust note.",
  rust_commit: "e77da7789ee19d516e44d4b4b389942290b7a0b2",
  rustc: "1.99.1",
  files: { trials: "api-examples/types/rust_trials.rs", runs: "api-examples/types/rust_runs.rs" },
  apis: [
    { lib: "mpl", id: "raw-aes-keyring", name: "Raw AES keyring", group: "Keyrings", call: "RawAesKeyring::builder()",
      options: [{ key: WRAP, rust_key: "mpl/RawAesKeyring.wrapping_key", name: "wrapping_key", takes: "impl Into<Vec<u8>>" }] },
    { lib: "esdk", id: "encrypt", name: "Encrypt", group: "Client", call: "client", options: [
      { key: PLAIN, rust_key: "esdk/encrypt.plaintext", name: "plaintext", takes: "&[u8]" },
      { key: KEYRING, rust_key: "esdk/encrypt.keyring", name: "keyring", takes: "impl IntoShared<SharedKeyring>" }] },
    { lib: "esdk", id: "decrypt", name: "Decrypt", group: "Client", call: "client",
      options: [{ key: CIPHER, rust_key: "esdk/decrypt.ciphertext", name: "ciphertext", takes: "&[u8]" }] },
    { lib: "mpl", id: "default-cmm", name: "Default CMM", group: "CMMs", call: "DefaultCmm",
      options: [{ key: CMM_KEYRING, rust_key: "mpl/DefaultCmm.keyring", name: "keyring", takes: "impl IntoShared<SharedKeyring>" }] },
  ],
  rows: {
    [WRAP]: [
      ROW("Vec<u8>", 0, ".wrapping_key(x)", "bytes", { trial: 5, test: 6, run: { builds: true, same: true } }),
      ROW("&str", 0, ".wrapping_key(x)", "text", { trial: 6, test: 16, run: { builds: true, same: true } }),
    ],
    [PLAIN]: [
      ROW("&[u8]", 0, ".encrypt().plaintext(x)", "bytes", { trial: 10, test: 20, run: { builds: true, same: true, copies: false } }),
      ROW("[u8; 32]", 0, ".encrypt().plaintext(&x)", "bytes", { trial: 11, test: 30, run: { skipped: "the value is not 32 bytes" } }),
      ROW("String", 1, ".encrypt().plaintext(x.as_bytes())", "text", { trial: 12, test: 40, fix: "x.as_bytes()", run: { builds: true, same: true, copies: true } }),
      ROW("PathBuf", 2, ".encrypt().plaintext(&std::fs::read(x).unwrap())", "path", { trial: 13, test: 50, run: { builds: true, same: false } }),
      ROW("char", null, "", "text", { trial: null }),
    ],
    [KEYRING]: [
      ROW("RawAesKeyring", 0, ".encrypt().keyring(x)", "component", { trial: 14 }),
      ROW("SharedKeyring", 0, ".encrypt().keyring(x)", "component", { trial: 15 }),
      ROW("&RawAesKeyring", 1, ".encrypt().keyring(x.clone())", "component", { trial: 16 }),
    ],
    [CMM_KEYRING]: [ROW("RawAesKeyring", 0, "::new(x)", "component", { trial: 17 })],
    [CIPHER]: [
      ROW("&[u8]", 0, ".decrypt().ciphertext(x)", "bytes", { trial: 20, test: 60, run: { builds: true, same: true, copies: false } }),
      ROW("String", 1, ".decrypt().ciphertext(x.as_bytes())", "text",
        { trial: 21, test: 70, run: { builds: false, error: "Serialization(SerializationError { message: \"input appears to be Base64-encoded\" })" } }),
    ],
  },
  about: { RawAesKeyring: { parts: [{ name: "RawAesKeyring", text: "A keyring with a local AES key.", from: "aws-crypto-mpl", url: "https://example.com/raw" }],
    held: { text: "You build one with RawAesKeyring::builder(), on the Raw AES keyring tab.", why: null, examples: [] } } },
  handles: { SharedKeyring: { group: "Keyrings", members: ["RawAesKeyring"] } },
};

const OTHERS = {
  note: "Others note.",
  apis: [
    { lib: "mpl", id: "raw-aes-keyring", name: "Raw AES keyring", group: "Keyrings",
      options: [{ key: WRAP, name: "wrappingKey", names: { java: "wrappingKey" }, takes: { java: "ByteBuffer" } }] },
    { lib: "mpl", id: "raw-rsa-keyring", name: "Raw RSA keyring", group: "Keyrings",
      options: [{ key: RSA, name: "publicKey", names: { java: "publicKey" }, takes: { java: "ByteBuffer" } }] },
    { lib: "esdk", id: "encrypt", name: "Encrypt", group: "Client",
      options: [{ key: PLAIN, name: "plaintext", names: { java: "plaintext", python: "source" }, takes: { java: "byte[] | String", python: "bytes" } }] },
  ],
  rows: {
    [WRAP]: { java: [ROW("String", 1, "ByteBuffer.wrap(x.getBytes())", "text")] },
    [RSA]: { java: [ROW("ByteBuffer", 0, "CreateRawRsaKeyringInput.builder().publicKey(x)", "bytes")] },
    [PLAIN]: { java: [ROW("byte[]", 0, "crypto.encryptData(keyring, x)", "bytes"), ROW("String", 0, "crypto.encryptString(provider, x, context)", "text")],
      python: [ROW("bytes", 0, "client.encrypt(source=x)", "bytes")] },
  },
  about: { java: {} },
};

const RULES = { rules: {
  [WRAP]: { refuse: ["text", "optional text"], why: "Text is not a key." },
  [CIPHER]: { refuse: ["text", "optional text"], why: "Ciphertext text is base64." },
} };

const HIT = (repo, file, line, code, source, more = {}) => ({ repo, path: file, line, language: "python",
  url: `https://github.com/${repo}/blob/c0ffee/${file}#L${line}`, code, assignment: null, blob: null, aws_copy: false, source, ...more });
const USAGE = {
  generated_at: "2026-11-25T22:07:40Z",
  languages: { python: { files: 5, repos: 4, calls: 6 }, java: { files: 1, repos: 1, calls: 1 } },
  search: { skipped: ["forks", "private repos"], sources: "Hits in one file count as one source." },
  apis: { "esdk|encrypt": { plaintext: [
    { conversion: ".encode()", from: "a string", count: 5, languages: { python: 5 }, examples: [], repos: 4, sources: 3, aws_copies: 1,
      hits: [
        HIT("acme/one", "app/main.py", 10, "client.encrypt(source=data.encode())", 0),
        HIT("acme/one", "app/main.py", 20, "client.encrypt(source=text.encode())", 0),
        HIT("acme/two", "a/b/crypto.py", 5, "client.encrypt(source=body.encode())", 1),
        HIT("acme/three", "c/b/crypto.py", 5, "client.encrypt(source=body.encode())", 1),
        HIT("acme/four", "run.py", 3, "client.encrypt(source=x)", 2, { assignment: "x = raw.encode()" }),
        HIT("acme/five", "aws_lambda_powertools/kms.py", 7, "client.encrypt(source=y.encode())", undefined, { aws_copy: true }),
      ] },
    { conversion: ".getBytes(...)", from: "a string", count: 1, languages: { java: 1 }, examples: [], repos: 1, sources: 1, aws_copies: 0,
      hits: [HIT("acme/six", "Main.java", 9, "crypto.encryptData(k, s.getBytes(UTF_8))", 0, { language: "java" })] },
  ] } },
};

const PROPOSALS = {
  checked: "Proposals: compiled.",
  options: { "esdk/encrypt.plaintext": { why: "Takes text too.", languages: { rust: {
    signature: "plaintext(impl Into<Plaintext>)",
    breaks: [".encrypt().plaintext(x.as_ref()) with Vec<u8>"],
    rows: [ROW("&[u8]", 0, ".encrypt().plaintext(x)", "bytes", { today: 0 }), ROW("String", 0, ".encrypt().plaintext(&x)", "text", { today: 1, proposed: true })],
  } } } },
};

// Opens the page with these data files. A file that is null fails to load. With `github`, a map from an API path to
// its reply, the page has a token and reads CI runs from that map.
async function open(files = {}, search = "", github = null) {
  const all = { "types-rust.json": RUST, "types-others.json": OTHERS, "usage.json": USAGE, "expectations.json": RULES,
    "proposals.json": null, ...files };
  const els = {};
  const document = {
    getElementById: id => els[id] || (els[id] = { innerHTML: "", textContent: "", on: {}, classList: { add() {}, remove() {} },
      style: { setProperty() {} }, addEventListener(type, f) { this.on[type] = f; } }),
    querySelectorAll: () => [],
  };
  const API = "https://api.github.com/";
  const fetch = async name => {
    if (name.startsWith(API)) {
      const reply = github && github[name.slice(API.length)];
      return { ok: reply !== undefined, status: reply === undefined ? 404 : 200,
        json: async () => structuredClone(reply), arrayBuffer: async () => reply };
    }
    return { ok: all[name] !== null && all[name] !== undefined, json: async () => structuredClone(all[name]) };
  };
  const localStorage = { getItem: key => (github && key === "github-dashboard-token" ? "a token" : null), setItem() {}, removeItem() {} };
  new Function("document", "fetch", "location", "localStorage", SCRIPT)(document, fetch, { search }, localStorage);
  await new Promise(resolve => setTimeout(resolve, github ? 200 : 20));
  // A click on an element in #id that matches each selector in `matches`, with that selector's dataset.
  const click = (id, matches) => els[id].on.click({ target: { closest: s => (s in matches ? { dataset: matches[s], classList: { add() {} } } : null) } });
  const page = {
    els,
    pickApi: key => {
      const [lib, id] = key.split("|");
      click("libs", { button: { lib } });
      const index = [...els.apis.innerHTML.matchAll(/data-api="(\d+)" data-id="([^"]+)"/g)].find(m => m[2] === id)[1];
      click("apis", { button: { api: index } });
    },
    pickLang: lang => click("langs", { button: { lang } }),
    chip: (key, lang, type) => {
      click("view", { ".chip": { key, lang, type } });
      return els.detail.innerHTML;
    },
    cust: (key, filter) => {
      click("view", { ".cust": { cust: key, kind: filter.kind || "", lang: filter.lang || "" } });
      return els.detail.innerHTML;
    },
    go: data => {
      click("detail", { "[data-go]": data });
      return els.detail.innerHTML;
    },
    back: () => {
      click("detail", { "[data-back]": {} });
      return els.detail.innerHTML;
    },
    openRow: id => click("view", { "tr[data-open]": { open: id } }),
    click,
    propose: key => click("view", { ".prop": { prop: key } }),
  };
  return page;
}

// The chips in some HTML, as {type: the chip's HTML}.
const chips = html => Object.fromEntries([...html.matchAll(/<span class="chip[^"]*"[^>]*data-type="([^"]*)">.*?<\/span>/g)].map(m => [unesc(m[1]), m[0]]));

// The column title above each type in one option's row of the map.
function columns(html, option) {
  const titles = [...html.matchAll(/<th[^>]*>(.*?)<\/th>/g)].map(m => unesc(m[1])).slice(1);
  const row = html.split("<tr>").find(r => r.includes(`<b>${option}</b>`));
  const out = {};
  row.split("<td").slice(2).forEach((cell, i) => {
    for (const type of Object.keys(chips(cell))) out[type] = titles[i];
  });
  return out;
}

test("each type sits under its number of calls", async () => {
  const page = await open();
  page.pickApi(PLAIN);
  assert.deepStrictEqual(columns(page.els.view.innerHTML, "plaintext"),
    { "&[u8]": "As is", "[u8; 32]": "As is", String: "One call", PathBuf: ">1 call", char: "No fix found" });
});

test("a library's tabs list every API that any language has, and say which a language lacks", async () => {
  const page = await open();
  page.pickApi(RSA);
  assert.deepStrictEqual([...page.els.apis.innerHTML.matchAll(/data-id="([^"]+)"/g)].map(m => m[1]), ["raw-aes-keyring", "raw-rsa-keyring", "default-cmm"]);
  assert.match(page.els.view.innerHTML, /Rust doesn't have the Raw RSA keyring yet\./);
  page.pickLang("java");
  assert.deepStrictEqual(Object.keys(chips(page.els.view.innerHTML)), ["ByteBuffer"]);
  page.els.libs.on.click({ target: { closest: () => ({ dataset: { lib: "dbesdk" } }) } });
  assert.match(page.els.view.innerHTML, /No DB-ESDK data yet/);
});

test("a rule marks an option that takes refused text as is", async () => {
  const page = await open();
  page.pickApi(WRAP);
  const map = chips(page.els.view.innerHTML);
  assert.match(map["&str"], /class="chip b0 warn"/);
  assert.doesNotMatch(map["Vec<u8>"], /warn/);
  assert.match(page.chip(WRAP, "rust", "&str"), /⚠ Rule: Takes text as is, which the rule refuses\. Text is not a key\./);
  page.pickLang("java");
  assert.match(page.chip(WRAP, "java", "String"), /✅ Rule: Needs a conversion, as the rule asks\./);
});

test("a Rust chip shows its call, says where it compiled, and links the code and the CI workflow", async () => {
  const page = await open();
  page.pickApi(PLAIN);
  const pane = page.chip(PLAIN, "rust", "String");
  assert.match(pane, /<pre>\/\/ You have x: String\nclient\.encrypt\(\)\.plaintext\(x\.as_bytes\(\)\)<\/pre>/);
  assert.match(pane, /One call: <code>as_bytes\(\)<\/code>\./);
  assert.match(pane, /✅ Compiled in the committed copy\./);
  const links = [...pane.matchAll(/href="([^"]*)"/g)].map(m => m[1]);
  for (const link of ["https://github.com/aws/aws-crypto-tools-commons/blob/main/api-examples/types/rust_trials.rs#L12",
    "https://github.com/aws/aws-crypto-tools-commons/blob/main/api-examples/types/rust_runs.rs#L40",
    "https://github.com/aws/aws-crypto-tools-rust/tree/e77da7789ee19d516e44d4b4b389942290b7a0b2",
    "https://github.com/aws/aws-crypto-tools-commons/actions/workflows/api-examples-types.yml?query=branch%3Amain"]) {
    assert.ok(links.includes(link), link);
  }
  assert.match(page.chip(PLAIN, "rust", "char"), /<pre>\/\/ You have x: char\n\/\/ No fix in the list works\.<\/pre>.*❌ No fix in the list compiled/);
});

test("links go to the branch that ?ref names", async () => {
  const page = await open({}, "?ref=lucmcdon/api-examples");
  page.pickApi(WRAP);
  const pane = page.chip(WRAP, "rust", "Vec<u8>");
  assert.match(pane, /blob\/lucmcdon\/api-examples\/api-examples\/types\/rust_trials\.rs#L5"/);
  assert.match(pane, /query=branch%3Alucmcdon%2Fapi-examples"/);
});

test("the pane says what the run found, and a failed run strikes its chip", async () => {
  const page = await open();
  page.pickApi(PLAIN);
  const ran = type => page.chip(PLAIN, "rust", type).match(/<li>([^<]*Ran[^<]*|⏭[^<]*)/)[1];
  assert.strictEqual(ran("&[u8]"), "✅ Ran: it works, and gives the same result as the reference value. Passing the value doesn't copy it. ");
  assert.strictEqual(ran("String"), "✅ Ran: it works, and gives the same result as the reference value. Passing the value copies it. ");
  assert.strictEqual(ran("PathBuf"), "❌ Ran: it works, but the result differs from the reference value. ");
  assert.strictEqual(ran("[u8; 32]"), "⏭ Not run: the value is not 32 bytes. ");
  const map = chips(page.els.view.innerHTML);
  assert.match(map.PathBuf, /failed.*✗/);
  assert.doesNotMatch(map["[u8; 32]"], /failed/);
  page.pickApi(CIPHER);
  assert.match(chips(page.els.view.innerHTML).String, /class="chip b1 failed".*String ✗/);
});

test("another language's chip shows its own code and says it is not compiled", async () => {
  const page = await open();
  page.pickApi(PLAIN);
  page.pickLang("java");
  assert.deepStrictEqual(Object.keys(chips(page.els.view.innerHTML)), ["byte[]", "String"]);
  const pane = page.chip(PLAIN, "java", "String");
  assert.match(pane, /<pre>\/\/ You have x: String\ncrypto\.encryptString\(provider, x, context\)<\/pre>/);
  assert.match(pane, /Not compiled or run\./);
  assert.doesNotMatch(pane, /rust_trials/);
});

test("a comparison row shows each language's cheapest type, and opens to list them all", async () => {
  const page = await open();
  page.pickApi(PLAIN);
  page.pickLang("compare");
  const row = kind => page.els.view.innerHTML.split("<tr").find(r => r.includes(`data-open="${PLAIN}|${kind}"`));
  assert.match(row("bytes"), /<td class="kind">▸ bytes<\/td><td class="ck"><span class="chip b0"[^>]*>as is<\/span><small>&amp;\[u8\] \+1<\/small>/);
  page.openRow(`${PLAIN}|bytes`);
  const detail = page.els.view.innerHTML.split('<tr class="detail">')[1].split("</tr>")[0];
  assert.deepStrictEqual(Object.keys(chips(detail)), ["&[u8]", "[u8; 32]", "byte[]", "bytes"]);
});

test("a customer cell in the comparison counts the sources with that kind of value, and opens every hit, grouped by source", async () => {
  const page = await open();
  page.pickApi(PLAIN);
  page.pickLang("compare");
  const row = page.els.view.innerHTML.split("<tr").find(r => r.includes(`data-open="${PLAIN}|text"`));
  assert.match(row, /<span class="cust" data-cust="esdk\|encrypt\|plaintext" data-kind="text" data-lang=""[^>]*>4 sources<\/span>/);
  assert.doesNotMatch(page.els.view.innerHTML, /\.encode\(\)/, "the table names no calls");
  const pane = page.cust(PLAIN, { kind: "text" });
  assert.match(pane, /Customers who have text, and convert it before the call · 4 sources/);
  const python = pane.split("<details").find(d => d.includes("<code>.encode()</code>"));
  assert.match(python, /from a string · 3 sources · 5 hits \(python 5\)/);
  const [counted, aws] = python.split("Copies of AWS code, not counted:");
  const links = text => [...text.matchAll(/<a href="([^"]*)"/g)].map(m => m[1]);
  assert.deepStrictEqual(links(counted), USAGE.apis["esdk|encrypt"].plaintext[0].hits.slice(0, 5).map(h => h.url));
  assert.deepStrictEqual(links(aws), ["https://github.com/acme/five/blob/c0ffee/aws_lambda_powertools/kms.py#L7"]);
  const sources = counted.split('<div class="source">').slice(1);
  assert.strictEqual(sources.length, 3);
  assert.match(sources[0], /^<span class="tag">2 calls in one file<\/span>.*data\.encode.*text\.encode/);
  assert.match(sources[1], /^<span class="tag">2 copies<\/span>/);
  assert.strictEqual(sources[1].match(/<code>/g).length, 1, "a line in several copies shows once");
  assert.match(sources[2], /^<div><code>client\.encrypt\(source=x\)<\/code><br><code>x = raw\.encode\(\)<\/code>/);
});

test("each language's view counts its own customers, and opens only that language's calls", async () => {
  const page = await open();
  page.pickApi(PLAIN);
  page.pickLang("java");
  const row = page.els.view.innerHTML.split("<tr>").find(r => r.includes("<b>plaintext</b>"));
  assert.match(row, /data-lang="java"[^>]*>1 source<\/span>/);
  const pane = page.cust(PLAIN, { lang: "java" });
  assert.match(pane, /Customers who write Java · 1 sources/);
  assert.match(pane, /\.getBytes\(\.\.\.\)/);
  assert.doesNotMatch(pane, /\.encode\(\)/);
  page.pickLang("python");
  assert.match(page.els.view.innerHTML.split("<tr>").find(r => r.includes("<b>source</b>")), /data-lang="python"[^>]*>3 sources<\/span>/);
});

test("the footer says how the customer search ran, and the header says where each part came from", async () => {
  const page = await open();
  assert.match(page.els.foot.textContent, /GitHub code search on 2026-11-25T22:07:40Z, 7 calls\. Skipped: forks; private repos\. Hits in one file count as one source\./);
  assert.strictEqual(page.els.run.innerHTML, "Rust: committed copy · Others: committed copy · Customers: committed copy");
  const without = await open({ "usage.json": null });
  without.pickApi(PLAIN);
  assert.match(without.els.view.innerHTML, /usage\.json didn't load, so customer counts are hidden/);
});

test("a proposal moves the types it makes cheaper, and the pane says what it was", async () => {
  const page = await open({ "proposals.json": PROPOSALS });
  page.pickApi(PLAIN);
  assert.doesNotMatch(page.els.view.innerHTML, /▲/);
  page.propose(PLAIN);
  const html = page.els.view.innerHTML;
  assert.deepStrictEqual(columns(html, "plaintext"), { "&[u8]": "As is", String: "As is" });
  assert.match(chips(html).String, /String ▲/);
  assert.match(html, /Breaks \.encrypt\(\)\.plaintext\(x\.as_ref\(\)\) with Vec&lt;u8&gt;/);
  assert.match(page.chip(PLAIN, "rust", "String"),
    /✏️ Proposed: <code>plaintext\(impl Into&lt;Plaintext&gt;\)<\/code>\. Compiled against a model of it, not run\. Today: one call\./);
});

test("a chip says why it sits where it does, and shows how to make the type", async () => {
  const rust = structuredClone(RUST);
  rust.rows[PLAIN][2].fix = "x.as_bytes()";
  rust.rows[PLAIN][0].fix = "x";
  rust.rows[KEYRING][2].fix = "x.clone()";
  rust.rows[WRAP][0] = { ...rust.rows[WRAP][0], fix: "&x" };
  rust.examples = { "Cow<str>": 'use std::borrow::Cow;\nlet x: Cow<str> = Cow::Borrowed("my text");' };
  rust.rows[PLAIN].push(ROW("Cow<str>", 1, ".encrypt().plaintext(x.as_bytes())", "text", { trial: 18, fix: "x.as_bytes()" }));
  const page = await open({ "types-rust.json": rust });
  page.pickApi(PLAIN);
  assert.match(page.chip(PLAIN, "rust", "&[u8]"), /As is: you pass it without a call\./);
  assert.match(page.chip(PLAIN, "rust", "Cow<str>"),
    /<pre>\/\/ You have:\nuse std::borrow::Cow;\nlet x: Cow&lt;str&gt; = Cow::Borrowed\(&quot;my text&quot;\);\n\n\/\/ You write:\nclient\.encrypt\(\)\.plaintext\(x\.as_bytes\(\)\)<\/pre>/);
  page.pickApi(WRAP);
  assert.match(page.chip(WRAP, "rust", "Vec<u8>"), /As is: <code>&amp;x<\/code> only lends it, so it is not a call\./);
  page.pickApi(KEYRING);
  assert.doesNotMatch(page.chip(KEYRING, "rust", "&RawAesKeyring"), /Where a customer gets one/);
});

test("a long call puts each step on its own line", async () => {
  const rust = structuredClone(RUST);
  rust.rows[PLAIN][3].code = ".encrypt().plaintext(&std::fs::read(x).unwrap()).frame_length(4096)";
  const page = await open({ "types-rust.json": rust });
  page.pickApi(PLAIN);
  assert.match(page.chip(PLAIN, "rust", "PathBuf"), /\nclient\n    \.encrypt\(\)\n    \.plaintext\(&amp;std::fs::read\(x\)\.unwrap\(\)\)\n    \.frame_length\(4096\)<\/pre>/);
});

test("explore this type opens the type explorer in the main view, with its group and the options it goes into", async () => {
  const page = await open();
  page.pickApi(KEYRING);
  assert.match(page.chip(KEYRING, "rust", "&RawAesKeyring"), /data-x="type" data-lang="rust" data-type="&amp;RawAesKeyring">explore this type →/);
  page.click("detail", { "[data-x], [data-xback], [data-xclose], [data-go]": { x: "type", lang: "rust", type: "RawAesKeyring" } });
  const type = page.els.view.innerHTML;
  assert.match(type, /<h2>RawAesKeyring <span class="sub">Rust<\/span><\/h2>/);
  assert.match(type, /A keyring with a local AES key\./);
  assert.match(type, /<div class="node grp"><a class="go" data-x="group" data-handle="SharedKeyring">Keyrings<\/a><\/div>/);
  const targets = [...type.matchAll(/data-go="chip" data-key="([^"]*)"/g)].map(m => m[1]);
  assert.deepStrictEqual(targets, [CMM_KEYRING, KEYRING]);
  assert.match(type, /Also held as <a class="go" data-x="type" data-lang="rust" data-type="&amp;RawAesKeyring">/);
  page.click("view", { "[data-x], [data-xback], [data-xclose], [data-go]": { x: "group", handle: "SharedKeyring" } });
  const group = page.els.view.innerHTML;
  assert.match(group, /<h2>Keyrings <span class="sub">Rust<\/span><\/h2>/);
  assert.deepStrictEqual([...group.matchAll(/data-go="chip" data-key="([^"]*)"/g)].map(m => m[1]), [CMM_KEYRING, KEYRING],
    "each option that takes a keyring shows once");
  page.click("view", { "[data-x], [data-xback], [data-xclose], [data-go]": { xback: "" } });
  assert.match(page.els.view.innerHTML, /<h2>RawAesKeyring/);
  page.click("view", { "[data-x], [data-xback], [data-xclose], [data-go]": { go: "chip", key: KEYRING, lang: "rust", type: "RawAesKeyring" } });
  assert.match(page.els.detail.innerHTML, /<h2>RawAesKeyring<\/h2>/);
  page.click("view", { "[data-x], [data-xback], [data-xclose], [data-go]": { go: "api", lib: "mpl", id: "raw-aes-keyring" } });
  assert.match(page.els.view.innerHTML, /<b>wrapping_key<\/b>/);
});

// The tests below read the committed data files.

test("every chip on the committed page opens its pane, in every library and language", async () => {
  const rust = committed("types-rust.json"), others = committed("types-others.json");
  const page = await open({ "types-rust.json": rust, "types-others.json": others, "usage.json": committed("usage.json"),
    "expectations.json": committed("expectations.json") });
  let opened = 0;
  for (const lib of ["esdk", "mpl"]) {
    page.els.libs.on.click({ target: { closest: () => ({ dataset: { lib } }) } });
    const count = [...page.els.apis.innerHTML.matchAll(/data-api="(\d+)"/g)].length;
    for (let i = 0; i < count; i++) {
      page.els.apis.on.click({ target: { closest: () => ({ dataset: { api: String(i) } }) } });
      for (const lang of ["rust", "java", "python", "dotnet", "go", "javascript", "compare"]) {
        page.pickLang(lang);
        for (const m of page.els.view.innerHTML.matchAll(/data-key="([^"]*)" data-lang="([^"]*)" data-type="([^"]*)"/g)) {
          assert.match(page.chip(unesc(m[1]), m[2], unesc(m[3])), /<h2>/);
          opened++;
        }
      }
    }
  }
  const rows = Object.values(rust.rows).reduce((n, r) => n + r.length, 0);
  assert.ok(opened > rows, `opened ${opened} chips for ${rows} Rust rows`);
});

test("each committed Rust row's links land on its trial and its test", () => {
  const rust = committed("types-rust.json");
  const trials = fs.readFileSync(path.join(ROOT, rust.files.trials), "utf8").split("\n");
  const runs = fs.readFileSync(path.join(ROOT, rust.files.runs), "utf8").split("\n");
  const rustKey = Object.fromEntries(rust.apis.flatMap(a => a.options.map(o => [o.key, o.rust_key])));
  let checked = 0;
  for (const [key, rows] of Object.entries(rust.rows)) {
    for (const row of rows.filter(r => r.trial)) {
      // The trial's call has full paths, and the row's call is how the page shows it.
      assert.ok(trials[row.trial - 1].endsWith(` // ${rustKey[key]}: ${row.type}`), `${key} ${row.type}: ${trials[row.trial - 1]}`);
      const call = trials[row.trial - 1].split("let _ = ")[1].split("; }")[0];
      assert.ok(call.replace(/\b(?:aws_crypto_mpl|aws_esdk)::(?:[a-z_]\w*::)*/g, "").endsWith(row.code), `${key} ${row.type}: ${call}`);
      checked++;
      // Only some options have run tests.
      if (!row.test) continue;
      assert.match(runs[row.test - 1], /^async fn run_\d+\(\) \{$/);
      assert.strictEqual(runs[row.test], `    // ${rustKey[key]}: ${row.type} passed as ${row.code}`);
    }
  }
  assert.ok(checked > 100, `checked ${checked} rows`);
});

// A zip with one stored (not compressed) file, like an artifact download.
function zipOf(name, text) {
  const file = Buffer.from(name), data = Buffer.from(text);
  const local = Buffer.alloc(30), central = Buffer.alloc(46), end = Buffer.alloc(22);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(file.length, 26);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(file.length, 28);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length + file.length, 12);
  end.writeUInt32LE(local.length + file.length + data.length, 16);
  const all = Buffer.concat([local, file, data, central, file, end]);
  return all.buffer.slice(all.byteOffset, all.byteOffset + all.length);
}

// The types workflow's runs: the daily one on Rust main, and one the PR review page started for a PR's commit.
const RUNS = "repos/aws/aws-crypto-tools-commons/actions/workflows/api-examples-types.yml/runs?branch=main&status=success&per_page=30";
const run = (id, event, display_title) => ({ id, event, display_title, html_url: `https://example.com/runs/${id}`, created_at: "2026-11-26T00:00:00Z", run_number: id });
const artifacts = id => ({ artifacts: [{ id: id * 10, name: "api-types-rust", expired: false }] });
const CI = {
  [RUNS]: { workflow_runs: [run(2, "workflow_dispatch", "API types for Rust a12add08"), run(1, "schedule", "API types for Rust main")] },
  "repos/aws/aws-crypto-tools-commons/actions/runs/2": run(2, "workflow_dispatch", "API types for Rust a12add08"),
  "repos/aws/aws-crypto-tools-commons/actions/runs/1/artifacts?per_page=100": artifacts(1),
  "repos/aws/aws-crypto-tools-commons/actions/runs/2/artifacts?per_page=100": artifacts(2),
  "repos/aws/aws-crypto-tools-commons/actions/artifacts/10/zip": zipOf("types-rust.json", JSON.stringify({ ...RUST, note: "Rust main." })),
  "repos/aws/aws-crypto-tools-commons/actions/artifacts/20/zip": zipOf("types-rust.json", JSON.stringify({ ...RUST, note: "Rust a12add08." })),
  "repos/aws/aws-crypto-tools-commons/actions/workflows/api-examples-shipped.yml/runs?branch=main&status=success&per_page=30": { workflow_runs: [] },
  "repos/aws/aws-crypto-tools-commons/actions/workflows/api-examples-usage.yml/runs?branch=main&status=success&per_page=30": { workflow_runs: [] },
};

test("the page shows Rust main, not a run that read a pull request's commit, unless ?run= names that run", async () => {
  assert.match((await open({}, "", CI)).els.foot.textContent, /^Rust main\./);
  const pr = await open({}, "?run=2", CI);
  assert.match(pr.els.foot.textContent, /^Rust a12add08\./);
  assert.match(pr.els.run.innerHTML, /Rust: <a href="https:\/\/example.com\/runs\/2"/);
});

test("?api= opens that API", async () => {
  const page = await open({}, "?api=mpl|default-cmm");
  assert.match(page.els.apis.innerHTML, /data-id="default-cmm" class="on"/);
  assert.match(page.els.view.innerHTML, /<b>keyring<\/b>/);
});
