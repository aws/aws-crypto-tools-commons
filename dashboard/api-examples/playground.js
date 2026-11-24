// The logic of the API examples playground, with no page code, so that
// playground.test.js can run it in node against real api-examples.json files.
//
// Each language repo's api-examples.json (schema 4, from
// api-examples/build_api_examples.py) gives every API a frame (the start and
// end of the call), choices (one setter line each, keyed by option row and
// "have", what the customer starts from), left-out results, and the calls
// that CI built and ran. The page shows one card per option. A pick maps each
// option row to a have, or to null when the call leaves the option out.
(function (exports) {
"use strict";

const OPTION_KINDS = new Set(["member", "extra"]);

// One library's APIs, merged across languages by API id. docs is {language: api-examples.json}.
function apisOf(docs, langs) {
  const apis = new Map();
  for (const lang of langs) {
    for (const api of docs[lang]?.apis || []) {
      const a = apis.get(api.id) || { id: api.id, group: api.group, name: api.name, byLang: {}, docs: {} };
      a.byLang[lang] = api;
      a.docs[lang] = docs[lang];
      apis.set(api.id, a);
    }
  }
  return [...apis.values()];
}

// The option cards of one API: its Smithy member and extra rows, merged across
// languages in the order that each language lists its rows. Each card lists
// every have that any language offers, in language order.
function optionsOf(api, langs) {
  const options = new Map();
  for (const lang of langs) {
    const a = api.byLang[lang];
    if (!a) continue;
    for (const r of a.rows) {
      if (!OPTION_KINDS.has(r.kind)) continue;
      const o = options.get(r.key) || options.set(r.key, { key: r.key, label: r.label, kind: r.kind, haves: [], byLang: {} }).get(r.key);
      for (const h of r.haves) if (!o.haves.includes(h)) o.haves.push(h);
      o.byLang[lang] = {
        ways: a.ways.filter(w => w.row === r.key && w.kind === "setter"),
        choices: a.choices.filter(c => c.row === r.key),
        leftOut: a.left_out.find(x => x.rows.length === 1 && x.rows[0] === r.key) || null,
      };
    }
  }
  return [...options.values()];
}

const offers = (option, lang) => (option.byLang[lang]?.ways.length || 0) > 0;
const choiceOf = (option, have, lang) => option.byLang[lang]?.choices.find(c => c.have === have) || null;

// The dropdown text for one have: it says when this language has no such choice.
const choiceLabel = (option, have, lang) => choiceOf(option, have, lang) ? have : `${have} (not in ${lang})`;

// The call that the page starts with: each option's default choice in this
// language (or in the first language that has one), and every other option left out.
function startPicks(options, lang, langs) {
  const picks = {};
  for (const o of options) {
    const order = [lang, ...langs.filter(l => l !== lang)];
    const def = order.map(l => o.byLang[l]?.choices.find(c => c.default)).find(Boolean);
    picks[o.key] = def ? def.have : null;
  }
  return picks;
}

const LABELS = {
  ok: () => "✅ tested, works",
  fails: s => `✅ tested, fails as expected: ${s.error}`,
  untested: () => "⚠️ not tested",
  absent: () => "— not offered",
  none: () => "— not offered",
};

// What one card's pick does in one language.
//   ok, fails: a test shows it works or fails (with error). where is that test.
//   untested: the language has the option but no test for this pick.
//   absent: the language does not have the option, and the pick sets it.
//   none: the language does not have the option, and the pick leaves it out, so it does nothing.
function status(option, have, lang) {
  let s;
  if (!offers(option, lang)) {
    s = { kind: have === null ? "none" : "absent" };
  } else if (have === null) {
    const lo = option.byLang[lang].leftOut;
    s = !lo ? { kind: "untested" } : { kind: lo.expect, error: lo.error, where: lo };
  } else {
    const c = choiceOf(option, have, lang);
    s = !c ? { kind: "untested" } : { kind: c.expect, error: c.error, where: c };
  }
  s.label = LABELS[s.kind](s);
  return s;
}

// What a frame's one-of group (such as keyring or CMM) does: none set, or
// two or more set, is its own failing part. null when exactly one is set.
function groupStatus(api, options, picks, lang) {
  const a = api.byLang[lang];
  const group = a?.frame?.one_of || [];
  if (!group.length) return null;
  const set = group.filter(row => picks[row] != null && options.some(o => o.key === row && offers(o, lang)));
  if (set.length === 1) return null;
  const same = rows => rows.length === group.length && group.every(g => rows.includes(g));
  const found = set.length === 0
    ? a.left_out.find(x => same(x.rows) && x.expect === "fails")
    : a.together.find(x => same(x.rows));
  const what = set.length === 0 ? `none of ${group.join(", ")}` : `more than one of ${group.join(", ")}`;
  return found ? { kind: "fails", error: found.error, where: found, what } : { kind: "untested", what };
}

// The call that CI built and ran with exactly these picks, if it is in this language's results.
function comboFor(api, picks, lang) {
  const results = api.byLang[lang]?.combos?.results || [];
  return results.find(r =>
    Object.entries(r.choices).every(([row, have]) => (picks[row] ?? null) === have)
    && Object.entries(picks).every(([row, have]) => have === null || row in r.choices)) || null;
}

// The verdict box: what the whole call does in one language, and the tests that show it.
function verdict(api, options, picks, lang) {
  const a = api.byLang[lang];
  if (!a?.frame) return { kind: "absent", text: `— ${lang} has no ${api.name}`, links: [], combo: null };
  const parts = options.map(o => ({ option: o, ...status(o, picks[o.key] ?? null, lang) }));
  const group = groupStatus(api, options, picks, lang);
  const named = p => p.option ? p.option.label : p.what;
  const all = group ? [...parts, group] : parts;
  const absent = all.filter(p => p.kind === "absent");
  const untested = all.filter(p => p.kind === "untested");
  const failing = all.filter(p => p.kind === "fails");
  const links = [a.frame, ...all.map(p => p.where).filter(Boolean)].map(w => ({ file: w.file, line: w.line }));
  const combo = comboFor(api, picks, lang);
  let kind, text;
  if (absent.length) {
    kind = "absent"; text = `— ${lang} has no ${absent.map(named).join(", ")}`;
  } else if (untested.length) {
    kind = "untested"; text = `⚠️ not tested: ${untested.map(named).join(", ")}`;
  } else if (failing.length === 0) {
    kind = "ok"; text = "✅ works";
  } else if (failing.length === 1) {
    kind = "fails"; text = `✅ fails as expected: ${failing[0].error}`;
  } else {
    kind = "fails"; text = `✅ fails: ${failing.length} parts fail (${failing.map(named).join(", ")})`;
  }
  return { kind, text, links, combo };
}

const indentOf = line => line.match(/^\s*/)[0];

// The indent of a setter line in this language, from any of its choices or its tail.
function setterIndent(a) {
  const line = a.choices[0]?.setter || a.frame?.tail?.[0] || "    ";
  return indentOf(line) || "    ";
}

// The call in one language: setup, head, one setter line per chosen option, tail.
// A pick that the language has no code for becomes a comment line.
function codeOf(api, options, picks, lang) {
  const a = api.byLang[lang];
  if (!a?.frame) return null;
  const setup = [...a.frame.setup], setters = [];
  for (const o of options) {
    const have = picks[o.key] ?? null;
    if (have === null) continue;
    const c = choiceOf(o, have, lang);
    if (c) {
      setup.push(...c.setup);
      setters.push(c.setter);
    } else {
      setters.push(`${setterIndent(a)}// ${o.label} from ${have}: no ${lang} example`);
    }
  }
  return [...setup, ...a.frame.head, ...setters, ...a.frame.tail];
}

// Fill {{name}} placeholders. A placeholder alone on a line takes a list of
// lines at its indent, as build_api_examples.render does.
function render(text, values) {
  return text.split("\n").flatMap(line => {
    const m = line.match(/^(\s*)\{\{([\w-]+)\}\}$/);
    if (m && Array.isArray(values[m[2]])) return values[m[2]].map(v => v ? m[1] + v : "");
    return [line.replace(/\{\{([\w-]+)\}\}/g, (x, k) => k in values ? String(values[k]) : x)];
  }).join("\n");
}

const snake = s => s.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/[^A-Za-z0-9]+/g, "_").replace(/^_|_$/g, "").toLowerCase();

// A ready-to-paste test, in this language's marker format, for one pick that
// the language has no test for. The call sets every other option to its
// default choice, so it builds the whole object, as the other example tests do.
function newTest(api, options, option, have, lang) {
  const a = api.byLang[lang];
  const doc = api.docs?.[lang];
  const template = doc?.templates?.["new-test"];
  if (!a?.frame || !template) return null;
  const todo = doc.templates.todo || "todo";
  const way = option.byLang[lang]?.ways[0]?.id || option.key;
  const setup = [], setters = [];
  for (const o of options) {
    if (o === option) {
      if (have !== null) setters.push("// api-example: setter", `.${way}(${todo})`);
      continue;
    }
    const def = o.byLang[lang]?.choices.find(c => c.default);
    if (def) { setup.push(...def.setup); setters.push(def.setter.trim()); }
  }
  const indent = setterIndent(a);
  const marker = have === null
    ? `// api-example: api=${api.id} way=${way} left-out`
    : `// api-example: api=${api.id} way=${way} have="${have}"`;
  const code = [...a.frame.setup, marker, ...setup, ...(setup.length ? ["// api-example: call"] : []),
    ...a.frame.head, ...setters.map(s => indent + s), ...a.frame.tail, "// api-example: end"];
  return render(template, { name: snake(`${option.label} ${have === null ? "left out" : have}`), code });
}

// What changed between the default branch's files and a PR's (or branch's)
// files: APIs, options and haves that are new or removed, and APIs whose
// frame or choices changed. base and head are apisOf() results.
function diffApis(base, head, langs) {
  const out = { api: {}, option: {}, have: {}, removedApis: [], removedOptions: {}, removedHaves: {} };
  const baseById = new Map(base.map(a => [a.id, a]));
  const headIds = new Set(head.map(a => a.id));
  for (const a of base) if (!headIds.has(a.id)) { out.api[a.id] = "removed"; out.removedApis.push(a); }
  for (const a of head) {
    const b = baseById.get(a.id);
    if (!b) { out.api[a.id] = "new"; continue; }
    // A Smithy member that no language offers is a row on every page, so it is not new or removed.
    const offered = x => optionsOf(x, langs).filter(o => langs.some(l => offers(o, l)));
    const before = new Map(offered(b).map(o => [o.key, o]));
    const after = offered(a);
    let changed = false;
    for (const o of after) {
      const old = before.get(o.key);
      if (!old) { out.option[`${a.id}|${o.key}`] = "new"; changed = true; continue; }
      for (const h of o.haves) if (!old.haves.includes(h)) { out.have[`${a.id}|${o.key}|${h}`] = "new"; changed = true; }
      const gone = old.haves.filter(h => !o.haves.includes(h));
      for (const h of gone) out.have[`${a.id}|${o.key}|${h}`] = "removed";
      if (gone.length) { out.removedHaves[`${a.id}|${o.key}`] = gone; changed = true; }
    }
    const keys = new Set(after.map(o => o.key));
    const gone = [...before.values()].filter(o => !keys.has(o.key));
    for (const o of gone) out.option[`${a.id}|${o.key}`] = "removed";
    if (gone.length) { out.removedOptions[a.id] = gone; changed = true; }
    const code = x => JSON.stringify(langs.map(l => x.byLang[l] && [x.byLang[l].frame,
      x.byLang[l].choices.map(c => [c.row, c.have, c.setup, c.setter, c.expect, c.error])]));
    if (changed || code(a) !== code(b)) out.api[a.id] = "changed";
  }
  return out;
}

// Nav order: changed, new and removed APIs first, then the rest, each by name.
function navOrder(apis, diff) {
  const rank = a => (diff && diff.api[a.id] ? 0 : 1);
  return [...apis].sort((x, y) => rank(x) - rank(y) || x.name.localeCompare(y.name));
}

// "owner/repo#12" -> { repo, number }, or null for a branch name.
function parsePr(text) {
  const m = (text || "").trim().match(/^([\w.-]+\/[\w.-]+)#(\d+)$/);
  return m ? { repo: m[1], number: Number(m[2]) } : null;
}

Object.assign(exports, {
  apisOf, optionsOf, offers, choiceOf, choiceLabel, startPicks, status, groupStatus, comboFor, verdict,
  codeOf, newTest, render, diffApis, navOrder, parsePr,
});
})(typeof module !== "undefined" ? module.exports : (window.Playground = {}));
