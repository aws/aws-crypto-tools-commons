// Run with: node --test dashboard/api-examples/
// testdata/rust-mpl.json is real build_api_examples.py output for the Rust MPL.
// testdata/java-mpl.json is a small hand-written Java file.
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const P = require("./playground.js");

const LANGS = ["rust", "java"];
const read = name => JSON.parse(fs.readFileSync(path.join(__dirname, "testdata", name), "utf8"));
const docs = () => ({ rust: read("rust-mpl.json"), java: read("java-mpl.json") });

function api(id, d = docs()) {
  const a = P.apisOf(d, LANGS).find(x => x.id === id);
  return { a, options: P.optionsOf(a, LANGS) };
}
const option = (options, key) => options.find(o => o.key === key);

test("options merge every language's haves, and the dropdown marks the ones a language lacks", () => {
  const { options } = api("raw-aes-keyring");
  assert.deepStrictEqual(options.map(o => o.key), ["keyNamespace", "keyName", "wrappingKey", "wrappingAlg"]);
  const keyName = option(options, "keyName"), wrappingKey = option(options, "wrappingKey");
  assert.deepStrictEqual(keyName.haves, ["a string", "a string from your config"]);
  assert.strictEqual(P.choiceLabel(keyName, "a string", "java"), "a string");
  assert.strictEqual(P.choiceLabel(keyName, "a string from your config", "java"), "a string from your config (not in java)");
  assert.strictEqual(wrappingKey.haves.at(-1), "a SecretKey");
  assert.strictEqual(P.choiceLabel(wrappingKey, "a SecretKey", "rust"), "a SecretKey (not in rust)");
});

test("the starting Rust call works, ran in CI, and joins the default fragments", () => {
  const { a, options } = api("raw-aes-keyring");
  const picks = P.startPicks(options, "rust", LANGS);
  const v = P.verdict(a, options, picks, "rust");
  assert.strictEqual(v.text, "✅ works");
  assert.ok(v.combo, "the starting call is in CI's results");
  assert.strictEqual(v.combo.outcome, "pass");
  assert.deepStrictEqual(P.codeOf(a, options, picks, "rust"), [
    "let wrapping_key: Vec<u8> = wrapping_key_from_secret_store();",
    "let raw_aes_keyring = RawAesKeyring::builder()",
    '    .key_namespace("my-key-namespace")',
    '    .key_name("my-key-name")',
    "    .wrapping_key(wrapping_key)",
    "    .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)",
    "    .build()?;",
  ]);
  assert.ok(v.links.some(l => l.file === "mpl/tests/api_examples/raw_aes_keyring.rs"));
  assert.deepStrictEqual(option(options, "keyName").byLang.rust.choices[0].alts.map(x => x.setter.trim()),
    ['.set_key_name(Some("my-key-name".to_string()))']);
});

test("a choice only Java has is not tested in Rust, and Copy as a new test fills in the other defaults", () => {
  const { a, options } = api("raw-aes-keyring");
  const wrappingKey = option(options, "wrappingKey");
  const picks = { ...P.startPicks(options, "rust", LANGS), wrappingKey: "a SecretKey" };
  assert.strictEqual(P.status(wrappingKey, "a SecretKey", "rust").label, "⚠️ not tested");
  assert.strictEqual(P.verdict(a, options, picks, "rust").text, "⚠️ not tested: wrappingKey");
  assert.strictEqual(P.comboFor(a, picks, "rust"), null);
  assert.strictEqual(P.newTest(a, options, wrappingKey, "a SecretKey", "rust"), [
    "#[tokio::test]",
    "async fn wrapping_key_a_secret_key() -> Result<(), Error> {",
    '    // api-example: api=raw-aes-keyring way=wrapping_key have="a SecretKey"',
    "    let raw_aes_keyring = RawAesKeyring::builder()",
    '        .key_namespace("my-key-namespace")',
    '        .key_name("my-key-name")',
    "        // api-example: setter",
    "        .wrapping_key(todo!())",
    "        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)",
    "        .build()?;",
    "    // api-example: end",
    "    // TODO: check the result.",
    "    Ok(())",
    "}",
  ].join("\n"));
});

test("Java: a missing required option fails as tested, and an option Java lacks is not offered", () => {
  const { a, options } = api("raw-aes-keyring");
  const picks = { keyNamespace: null, keyName: null, wrappingKey: "a SecretKey", wrappingAlg: null };
  assert.strictEqual(P.status(option(options, "keyName"), null, "java").label,
    "✅ tested, fails as expected: IllegalArgumentException");
  assert.strictEqual(P.status(option(options, "keyNamespace"), null, "java").label, "— not offered");
  const v = P.verdict(a, options, picks, "java");
  assert.strictEqual(v.text, "✅ fails as expected: IllegalArgumentException");
  assert.deepStrictEqual(v.links.map(l => l.line), [10, 40, 30]);
  assert.strictEqual(P.verdict(a, options, { ...picks, keyNamespace: "a string" }, "java").text, "— java has no keyNamespace");
  assert.deepStrictEqual(P.codeOf(a, options, { ...picks, keyName: "a string from your config" }, "java"), [
    "SecretKey wrappingKey = keyFromSecretStore();",
    "RawAesKeyring keyring = RawAesKeyring.builder()",
    "    // keyName from a string from your config: no java example",
    "    .wrappingKey(wrappingKey)",
    "    .build();",
  ]);
});

test("two failing parts just fail, and a failing fragment fails with its error", () => {
  const { a, options } = api("raw-aes-keyring");
  const start = P.startPicks(options, "rust", LANGS);
  const bad = { ...start, wrappingKey: "a key of the wrong length" };
  assert.strictEqual(P.verdict(a, options, bad, "rust").text, "✅ fails as expected: validation");
  assert.strictEqual(P.verdict(a, options, { ...bad, keyName: null }, "rust").text,
    "✅ fails: 2 parts fail (keyName, wrappingKey)");
});

test("a one-of group fails with none or both set, and an optional option left out works", () => {
  const { a, options } = api("hierarchical-keyring");
  const start = P.startPicks(options, "rust", LANGS);
  assert.strictEqual(P.verdict(a, options, start, "rust").text, "✅ works");
  assert.strictEqual(P.status(option(options, "cache"), null, "rust").label, "✅ tested, works");
  assert.strictEqual(P.verdict(a, options, { ...start, branchKeyId: null }, "rust").text, "✅ fails as expected: validation");
  assert.strictEqual(P.verdict(a, options, { ...start, branchKeyIdSupplier: "a branch key ID supplier" }, "rust").text,
    "✅ fails as expected: validation");
});

test("PR mode tags new and removed APIs, options and haves, and puts changed APIs first", () => {
  const head = docs(), base = docs();
  const raw = base.rust.apis.find(x => x.id === "raw-aes-keyring");
  raw.rows = raw.rows.filter(r => r.key !== "wrappingAlg");
  raw.ways = raw.ways.filter(w => w.row !== "wrappingAlg");
  raw.rows.find(r => r.key === "keyName").haves.push("an old have");
  raw.choices.push({ ...raw.choices.find(c => c.row === "keyName"), have: "an old have", default: false });
  base.rust.apis.push({ ...raw, id: "gone-keyring", name: "Gone keyring" });
  head.rust.apis = head.rust.apis.filter(x => x.id !== "default-cmm");
  const d = P.diffApis(P.apisOf(base, LANGS), P.apisOf(head, LANGS), LANGS);
  assert.strictEqual(d.api["raw-aes-keyring"], "changed");
  assert.strictEqual(d.api["gone-keyring"], "removed");
  assert.strictEqual(d.api["default-cmm"], "removed");
  assert.strictEqual(d.api["hierarchical-keyring"], undefined);
  assert.strictEqual(d.option["raw-aes-keyring|wrappingAlg"], "new");
  assert.strictEqual(d.have["raw-aes-keyring|keyName|an old have"], "removed");
  assert.strictEqual(d.have["raw-aes-keyring|wrappingKey|a SecretKey"], undefined);
  const order = P.navOrder(P.apisOf(head, LANGS), d).map(x => x.id);
  assert.deepStrictEqual(order, ["raw-aes-keyring", "hierarchical-keyring"]);
});

// The compare matrix cell symbols, by option and have (null is leave it out), per language.
function symbols(options, key, a) {
  const rows = P.matrixRows(a, option(options, key), LANGS, null);
  return Object.fromEntries(rows.map(r => [r.have, Object.fromEntries(LANGS.map(l => [l, r.cells[l].symbol]))]));
}

test("compare matrix: a shared choice works in both, a Java-only choice is not offered in Rust", () => {
  const { a, options } = api("raw-aes-keyring");
  assert.deepStrictEqual(symbols(options, "keyName", a)["a string"], { rust: "✅", java: "✅" });
  assert.deepStrictEqual(symbols(options, "wrappingKey", a)["a SecretKey"], { rust: "--", java: "✅" });
  assert.strictEqual(P.cellOf(option(options, "keyName"), "a string", "java").title, 'java: .keyName("my-key-name")');
});

test("compare matrix: a rejected choice and a rejected leave-it-out show the error", () => {
  const { a, options } = api("raw-aes-keyring");
  assert.strictEqual(symbols(options, "wrappingKey", a)["a key of the wrong length"].rust, "❌");
  assert.deepStrictEqual(symbols(options, "keyName", a)[null], { rust: "❌", java: "❌" });
  assert.strictEqual(P.cellOf(option(options, "keyName"), null, "java").title, "java: IllegalArgumentException · left out");
});

test("clicking a compare cell picks that language and that choice", () => {
  const { a, options } = api("raw-aes-keyring");
  const index = options.findIndex(o => o.key === "keyName");
  const html = P.matrixHtml(a, [{ option: options[index], index }], LANGS, null, false);
  const have = option(options, "keyName").haves.indexOf("a string from your config");
  const cell = html.match(new RegExp(`data-lang="rust" data-option="${index}" data-have="${have}"`));
  assert.ok(cell, "the cell carries its language, option and have");
  const start = P.startPicks(options, "java", LANGS);
  const next = P.pickCell(options, start, { lang: "rust", option: String(index), have: String(have) });
  assert.strictEqual(next.lang, "rust");
  assert.deepStrictEqual(next.picks, { ...start, keyName: "a string from your config" });
});

test("the branch box takes a branch or owner/repo#number", () => {
  assert.deepStrictEqual(P.parsePr("aws/aws-crypto-tools-rust#206"), { repo: "aws/aws-crypto-tools-rust", number: 206 });
  assert.strictEqual(P.parsePr("lucmcdon/api-examples"), null);
});

// testdata/java-mpl-shipped.json is real build_api_examples.py --shipped output for the released Java MPL.
test("a shipped column shows the signature of each type it takes, and does not offer the others", () => {
  const langs = ["rust", "java-shipped"];
  const d = { rust: read("rust-mpl.json"), "java-shipped": read("java-mpl-shipped.json") };
  const a = P.apisOf(d, langs).find(x => x.id === "raw-aes-keyring");
  const options = P.optionsOf(a, langs);
  const wrappingKey = option(options, "wrappingKey");
  assert.ok(wrappingKey.haves.includes("a byte buffer"));
  assert.deepStrictEqual(P.cellOf(wrappingKey, "a byte buffer", "java-shipped"), {
    kind: "shipped", symbol: "📦",
    title: "java-shipped: 📦 shipped, not tested here · CreateRawAesKeyringInput.builder().wrappingKey(ByteBuffer)" });
  assert.strictEqual(P.cellOf(wrappingKey, "bytes in memory", "java-shipped").kind, "absent");
  assert.strictEqual(P.cellOf(wrappingKey, "a byte buffer", "rust").kind, "absent");
  assert.strictEqual(P.status(wrappingKey, null, "java-shipped").label, "📦 shipped, not tested here");

  const picks = { keyNamespace: "a string", keyName: "a string", wrappingKey: "a byte buffer", wrappingAlg: "AesWrappingAlg" };
  assert.strictEqual(P.verdict(a, options, picks, "java-shipped").text, "📦 shipped, not tested here");
  assert.strictEqual(P.verdict(a, options, { ...picks, wrappingKey: "bytes in memory" }, "java-shipped").text,
    "— java-shipped has no wrappingKey");
  assert.deepStrictEqual(P.codeOf(a, options, { wrappingKey: "a byte buffer" }, "java-shipped"), [
    "materialProviders.CreateRawAesKeyring(CreateRawAesKeyringInput)",
    "CreateRawAesKeyringInput.builder().wrappingKey(ByteBuffer)",
  ]);
  assert.strictEqual(P.shippedLabel(d["java-shipped"]), "Java (1.x shipped)");
  assert.strictEqual(P.shippedLabel({ language: "go", shipped: { version: "0.4.0" } }), "Go (0.4 shipped)");
});
