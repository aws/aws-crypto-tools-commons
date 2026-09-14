"""Render the DB-ESDK TestServer run summary for the GitHub Actions Summary page.

Reads the JUnit XML the Tests suite writes and prints Markdown to stdout: a
cross-language encrypt x decrypt coverage matrix, a failed-tests table, a
skipped-by-reason table (with the language(s) each reason applies to), and a
known-bugs table that flags any declared bug which stopped reproducing (that
fails the run until its id is removed from the server's bug-config.json).

Usage: python3 ci_summary.py <junit-results-dir>
"""
import glob, html, re, sys
import xml.etree.ElementTree as ET
from collections import defaultdict

TR = sys.argv[1]
files = sorted(glob.glob(TR + "/**/*.xml", recursive=True))

passed = failed = skipped = total = 0
cell = defaultdict(lambda: {"pass": 0, "fail": 0, "skip": 0})   # (enc,dec) pair
local = defaultdict(lambda: {"pass": 0, "fail": 0, "skip": 0})  # single target
skip_feature = defaultdict(int)
skip_bug = defaultdict(int)
skip_feat_langs = defaultdict(set)
skip_bug_langs = defaultdict(set)
bug_fixed = defaultdict(set)
catcount = defaultdict(lambda: {"pass": 0, "fail": 0, "skip": 0})  # feature/category
catclasses = defaultdict(set)  # category -> set of test-class simple names
failures = []
targets = set()

pair_re = re.compile(r'^(.*?)\s+([a-z0-9]+-v[0-9]+)->([a-z0-9]+-v[0-9]+)$')
local_re = re.compile(r'^(.*?)\s+([a-z0-9]+-v[0-9]+)$')

for f in files:
    try:
        root = ET.parse(f).getroot()
    except ET.ParseError:
        continue
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    for s in suites:
        suite_fqcn = s.get("name", "?")
        suite = suite_fqcn.split(".")[-1]
        # Category = the package segment after '...tests.' (e.g. item, search,
        # wire, transforms, structured, compatibility), else the class name.
        category = (suite_fqcn.split(".tests.")[-1].split(".")[0]
                    if ".tests." in suite_fqcn else suite)
        catclasses[category].add(suite)
        for tc in s.findall("testcase"):
            name = html.unescape(tc.get("name", ""))
            total += 1
            fe, ee, se = tc.find("failure"), tc.find("error"), tc.find("skipped")
            status = "fail" if (fe is not None or ee is not None) else ("skip" if se is not None else "pass")
            catcount[category][status] += 1
            m = pair_re.match(name)
            key, bucket = None, None
            if m:
                method, enc, dec = m.group(1), m.group(2), m.group(3)
                targets.add(enc); targets.add(dec); key = (enc, dec); bucket = cell[key]
            else:
                m2 = local_re.match(name)
                method = m2.group(1) if m2 else name
                if m2:
                    targets.add(m2.group(2)); bucket = local[m2.group(2)]
            if bucket is not None:
                bucket[status] += 1
            if status == "pass":
                passed += 1
            elif status == "skip":
                skipped += 1
                msg = (se.get("message") or "").strip()
                fm = re.search(r'feature=(\S+)', msg)
                bm = re.search(r'KNOWN BUG (\S+)', msg)
                if fm:
                    skip_feature[fm.group(1)] += 1
                    lm = re.search(r'unsupported by \[([^\]]*)\]', msg)
                    if lm:
                        for lang in lm.group(1).split(","):
                            if lang.strip():
                                skip_feat_langs[fm.group(1)].add(lang.strip())
                elif bm:
                    skip_bug[bm.group(1)] += 1
                    dm = re.search(r'declared for (\S+)', msg)
                    if dm:
                        skip_bug_langs[bm.group(1)].add(dm.group(1))
                else:
                    skip_feature[msg[:40]] += 1
            else:
                failed += 1
                el = fe if fe is not None else ee
                detail = (el.get("message") or "").strip().splitlines()[0][:140] if el is not None else ""
                pair = f"{m.group(2)}→{m.group(3)}" if m else (method and "")
                bugm = re.search(r"known bug did not reproduce.*?remove '([^']+)' for (\S+)", detail)
                if bugm:
                    bug_fixed[bugm.group(1)].add(bugm.group(2))
                failures.append((suite, method.strip(), pair, detail))

CATEGORY_LABELS = {
    "item": "Item encryption (EncryptItem/DecryptItem)",
    "transforms": "DynamoDB request/response transforms",
    "search": "Searchable encryption (beacons)",
    "materials": "Keyrings & CMMs",
    "structured": "Structured encryption",
    "configuration": "Client configuration & validation",
    "compatibility": "Version & legacy compatibility",
    "wire": "Wire format & integrity",
}

def label(cat):
    return CATEGORY_LABELS.get(cat, cat.replace("-", " ").replace("_", " ").capitalize())

def esc(s):
    # Markdown-table cells: a literal '|' (even inside a code span) ends the
    # cell, so escape it. detail is already single-lined above.
    return str(s).replace("|", "\\|")

def c(b):
    parts = []
    if b["pass"]: parts.append(f"{b['pass']} ✅")
    if b["fail"]: parts.append(f"{b['fail']} ❌")
    if b["skip"]: parts.append(f"{b['skip']} skipped")
    return " · ".join(parts) if parts else "—"

ts = sorted(targets)
out = []
status = "✅ PASSED" if failed == 0 else "❌ FAILED"
out.append(f"## DB-ESDK TestServer — {status}\n")
out.append(f"**{passed} passed** · {failed} failed · {skipped} skipped · {total} executions\n")

out.append("### By category\n")
out.append("| Category | Test classes | passed | failed | skipped | total |")
out.append("|---|---|--:|--:|--:|--:|")
for catname in sorted(catcount, key=lambda k: -sum(catcount[k].values())):
    b = catcount[catname]
    tot_c = b["pass"] + b["fail"] + b["skip"]
    classes = ", ".join(f"`{esc(cls)}`" for cls in sorted(catclasses.get(catname, [])))
    out.append(f"| {esc(label(catname))} | {classes} | {b['pass']} | {b['fail']} | {b['skip']} | {tot_c} |")
out.append(f"| **Total** | | **{passed}** | **{failed}** | **{skipped}** | **{total}** |")
out.append("")

out.append("### Cross-language coverage — encrypt ↓ · decrypt →\n")
out.append("_Each cell is that encrypt→decrypt pair's result: ✅ passed · ❌ failed · N skipped._\n")
out.append("| enc ╲ dec | " + " | ".join(ts) + " |")
out.append("|" + "---|" * (len(ts) + 1))
for enc in ts:
    out.append("| **" + enc + "** | " + " | ".join(c(cell[(enc, dec)]) for dec in ts) + " |")
out.append("")
if local:
    out.append("_Target-local checks (run once per target, not paired):_ "
               + " · ".join(f"{t} {c(local[t])}" for t in ts) + "\n")

if failed:
    out.append(f"### ❌ Failed ({failed})\n")
    out.append("| Suite | Test | Pair | Detail |")
    out.append("|---|---|---|---|")
    for suite, method, pair, detail in failures[:50]:
        out.append(f"| {esc(suite)} | {esc(method)} | {esc(pair)} | {esc(detail)} |")
    if len(failures) > 50:
        out.append(f"| … | _and {len(failures)-50} more_ | | |")
    out.append("")

if skipped:
    out.append(f"### ⤼ Skipped ({skipped}) — by reason\n")
    out.append("| Reason | Language(s) | Count |")
    out.append("|---|---|--:|")
    for feat, n in sorted(skip_feature.items(), key=lambda x: -x[1]):
        langs = ", ".join(sorted(skip_feat_langs.get(feat, []))) or "—"
        out.append(f"| feature `{esc(feat)}` unsupported | {langs} | {n} |")
    for bug, n in sorted(skip_bug.items(), key=lambda x: -x[1]):
        langs = ", ".join(sorted(skip_bug_langs.get(bug, []))) or "—"
        out.append(f"| known bug `{esc(bug)}` | {langs} | {n} |")

if skip_bug or bug_fixed:
    out.append("")
    out.append("### 🐞 Known bugs\n")
    out.append("| Bug | Declared for | Tolerated (skips) | ⚠️ Fixed — remove declaration |")
    out.append("|---|---|--:|---|")
    for bug in sorted(set(skip_bug) | set(bug_fixed)):
        declared = ", ".join(sorted(skip_bug_langs.get(bug, set()) | bug_fixed.get(bug, set()))) or "—"
        fixed = ", ".join(sorted(bug_fixed.get(bug, set()))) or "—"
        out.append(f"| `{esc(bug)}` | {declared} | {skip_bug.get(bug, 0)} | {fixed} |")
    if bug_fixed:
        out.append("\n> ⚠️ A declared known bug stopped reproducing on the language(s) above — "
                   "the run FAILS until that id is removed from the server's `bug-config.json`.")
    out.append("")

print("\n".join(out))
