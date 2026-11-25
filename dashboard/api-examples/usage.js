// The "How customers call it" section of each option card, from usage.json
// (api-examples/usage_search.py): what public customer code does to a value
// before it passes it to this option, ranked by how many calls do it.
//
// A conversion is a candidate input type when the current language takes
// nothing that the customer had before it. For example, Rust plaintext takes
// "bytes in memory", so a Java caller's .getBytes(...) (from "a string") is a candidate.
(function (exports) {
"use strict";

const ARTIFACT = "api-examples-usage";
const REPO = "aws/aws-crypto-tools-commons";

// The conversions for one option, most calls first. lib is "mpl" or "esdk".
const conversionsOf = (usage, lib, apiId, optionKey) => usage?.apis?.[`${lib}|${apiId}`]?.[optionKey] || [];

// haves are the current language's "what the customer starts from" choices for the option.
const isCandidate = (conv, haves) => !!conv.from && !haves.some(h => h.toLowerCase().includes(conv.from.toLowerCase()));

const escape = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

function sectionHtml(usage, lib, apiId, option, lang) {
  const convs = conversionsOf(usage, lib, apiId, option.key);
  if (!convs.length) return "";
  const haves = option.byLang[lang]?.haves || [];
  const total = convs.reduce((n, c) => n + c.count, 0);
  const rows = convs.map(c => {
    const langs = Object.entries(c.languages).map(([l, n]) => `${l} ${n}`).join(", ");
    const from = c.from ? ` <span class="from">from ${escape(c.from)}</span>` : "";
    const tag = isCandidate(c, haves) ? ` <span class="tag candidate" title="${escape(lang)} takes no ${escape(c.from)} here">candidate</span>` : "";
    const links = c.examples.map((e, i) =>
      `<a href="${escape(e.url)}" target="_blank" title="${escape(`${e.repo}/${e.path}:${e.line}`)}">${i + 1}</a>`).join(" ");
    return `<li><code>${escape(c.conversion)}</code> ×${c.count}${from}${tag} <span class="langs">${escape(langs)}</span> ${links}</li>`;
  }).join("");
  return `<div class="usage"><h4>How customers call it <span>${total} calls in public code</span></h4><ol>${rows}</ol></div>`;
}

// The newest usage.json from the weekly search on the default branch, or the
// committed one when there is no artifact or it cannot be read.
// page holds the index.html helpers that read artifacts.
async function load(page) {
  try {
    const art = await page.findArtifact(REPO, ARTIFACT, "main");
    if (art) {
      const zip = await (await page.gh(`repos/${REPO}/actions/artifacts/${art.id}/zip`)).arrayBuffer();
      const e = page.zipEntries(zip).find(x => x.name.endsWith("usage.json"));
      if (e) return JSON.parse(await page.entryText(zip, e));
    }
  } catch (err) {
    console.warn("usage artifact:", err);
  }
  const resp = await fetch("usage.json");
  return resp.ok ? resp.json() : null;
}

Object.assign(exports, { conversionsOf, isCandidate, sectionHtml, load });
})(typeof module !== "undefined" ? module.exports : (window.Usage = {}));
