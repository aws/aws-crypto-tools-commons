// Run with: node --test dashboard/api-examples/usage.test.js
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const P = require("./playground.js");
const U = require("./usage.js");

const LANGS = ["rust", "java"];
const read = name => JSON.parse(fs.readFileSync(path.join(__dirname, "testdata", name), "utf8"));
const options = P.optionsOf(P.apisOf({ rust: read("rust-mpl.json"), java: read("java-mpl.json") }, LANGS)
  .find(a => a.id === "raw-aes-keyring"), LANGS);
const option = key => options.find(o => o.key === key);

const example = n => ({ repo: `acme/app${n}`, path: "Main.java", line: n, url: `https://github.com/acme/app${n}/blob/c0ffee/Main.java#L${n}` });
const USAGE = { apis: { "mpl|raw-aes-keyring": {
  wrappingKey: [
    { conversion: ".getBytes(...)", from: "a string", count: 4, languages: { java: 4 }, examples: [example(1), example(2)] },
    { conversion: "passed as is", from: null, count: 1, languages: { python: 1 }, examples: [example(3)] },
  ],
  keyName: [
    { conversion: "environment variable", from: "a string from your config", count: 2, languages: { java: 2 }, examples: [] },
    { conversion: "string literal", from: "a string", count: 1, languages: { java: 1 }, examples: [] },
  ],
} } };

// [conversion, candidate] of each row that the card shows, in order.
function rows(key, lang) {
  const html = U.sectionHtml(USAGE, "mpl", "raw-aes-keyring", option(key), lang);
  return [...html.matchAll(/<li><code>([^<]*)<\/code>(.*?)<\/li>/g)].map(m => [m[1], m[2].includes("candidate")]);
}

test("a conversion from something that the language does not take is a candidate", () => {
  assert.deepStrictEqual(rows("wrappingKey", "rust"), [[".getBytes(...)", true], ["passed as is", false]]);
  assert.deepStrictEqual(rows("keyName", "rust"), [["environment variable", false], ["string literal", false]]);
  assert.deepStrictEqual(rows("keyName", "java"), [["environment variable", true], ["string literal", false]]);
});

test("each conversion links its examples and the section counts every call", () => {
  const html = U.sectionHtml(USAGE, "mpl", "raw-aes-keyring", option("wrappingKey"), "rust");
  assert.match(html, /5 calls in public code/);
  assert.deepStrictEqual([...html.matchAll(/href="([^"]*)"/g)].map(m => m[1]), [example(1), example(2), example(3)].map(e => e.url));
});

test("an option that no customer call passes has no section", () => {
  assert.strictEqual(U.sectionHtml(USAGE, "mpl", "raw-aes-keyring", option("wrappingAlg"), "rust"), "");
  assert.strictEqual(U.sectionHtml(null, "mpl", "raw-aes-keyring", option("wrappingKey"), "rust"), "");
});

test("load prefers the search artifact and falls back to the committed file", async t => {
  const fromArtifact = { apis: { from: "artifact" } }, committed = { apis: { from: "committed" } };
  t.mock.method(global, "fetch", async name => ({ ok: name === "usage.json", json: async () => committed }));
  const page = art => ({
    findArtifact: async (repo, name, branch) => (repo === "aws/aws-crypto-tools-commons" && name === "api-examples-usage" && branch === "main" ? art : null),
    gh: async () => ({ arrayBuffer: async () => "zip" }),
    zipEntries: () => [{ name: "usage.json" }],
    entryText: async () => JSON.stringify(fromArtifact),
  });
  assert.deepStrictEqual(await U.load(page({ id: 7 })), fromArtifact);
  assert.deepStrictEqual(await U.load(page(null)), committed);
  const failing = { ...page({ id: 7 }), gh: async () => { throw new Error("401"); } };
  t.mock.method(console, "warn", () => {});
  assert.deepStrictEqual(await U.load(failing), committed);
});
