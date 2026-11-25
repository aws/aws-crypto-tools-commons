#!/usr/bin/env python3
"""Write usage.json: how public customer code calls the shipped ESDK and MPL today.

The API examples page shows it under each option, so a reviewer sees what
customers convert before they call us. Each conversion is a candidate input type.

The script runs GitHub code search for calls in each language, drops code that
is not customer code (AWS orgs, forks, private repos, copies of the libraries),
reads each file, and finds the argument of every option in smithy-names.json.
It then classifies the conversion that the argument does, or that the line
which assigns the argument's variable does (`.getBytes(UTF_8)`, `Buffer.from(`).

Usage:
  usage_search.py [--names api-examples/smithy-names.json] [--out dashboard/api-examples/usage.json]
                  [--max-pages 10]

Code search needs a token: GH_TOKEN, GITHUB_TOKEN, or `gh auth token`.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from build_api_examples import option_key

API = "https://api.github.com"
# Code search returns at most 1000 results: 10 pages of 100.
PAGE_SIZE = 100
MAX_EXAMPLES = 5
# How many lines above a call to look for the line that assigns an argument's variable.
LOOKBACK = 40
# AWS's own code: the libraries, their examples, and AWS samples.
AWS_OWNERS = {"aws", "awslabs", "aws-samples"}
# Vendored or built copies of a library, not code that calls it.
SKIP_PATH = re.compile(r"(^|/)(node_modules|site-packages|vendor|dist|build|target)/")
# Copies of a library's own source. Their calls into the library are not customer calls.
LIBRARY_COPY = re.compile(r"(^|/)(com/amazonaws/encryptionsdk|software/amazon/cryptography)/(?!.*[Ee]xample)")


# ---------- languages ----------

# For each language: the GitHub search language names, what an ESDK or MPL file
# imports (a search hit without it is someone else's encrypt()), and the
# searches. Code search splits code into words, so each search names whole words.
LANGUAGES = {
    "java": {
        "search": ["java"],
        "imports": r"com\.amazonaws\.encryptionsdk|software\.amazon\.cryptography\.(materialproviders|encryptionsdk)",
        "queries": [
            "com.amazonaws.encryptionsdk encryptData",
            "com.amazonaws.encryptionsdk decryptData",
            "AwsCrypto withCommitmentPolicy",
            "materialproviders CreateAwsKmsKeyringInput",
            "materialproviders CreateAwsKmsMultiKeyringInput",
            "materialproviders CreateRawAesKeyringInput",
            "materialproviders CreateAwsKmsHierarchicalKeyringInput",
        ],
    },
    "python": {
        "search": ["python"],
        "imports": r"aws_encryption_sdk|aws_cryptographic_material_providers",
        "queries": [
            "aws_encryption_sdk encrypt source",
            "aws_encryption_sdk decrypt source",
            "StrictAwsKmsMasterKeyProvider key_ids",
            "EncryptionSDKClient commitment_policy",
            "aws_cryptographic_material_providers CreateAwsKmsKeyringInput",
            "aws_cryptographic_material_providers CreateRawAesKeyringInput",
        ],
    },
    "javascript": {
        "search": ["javascript", "typescript"],
        "imports": r"@aws-crypto/",
        "queries": [
            "\"@aws-crypto/client-node\" encrypt",
            "\"@aws-crypto/client-browser\" encrypt",
            "KmsKeyringNode generatorKeyId",
            "RawAesKeyringNode unencryptedMasterKey",
        ],
    },
    "dotnet": {
        "search": ["csharp"],
        "imports": r"AWS\.Cryptography\.(EncryptionSDK|MaterialProviders)",
        "queries": [
            "AWS.Cryptography.EncryptionSDK EncryptInput",
            "AWS.Cryptography.EncryptionSDK DecryptInput",
            "AWS.Cryptography.MaterialProviders CreateAwsKmsKeyringInput",
            "AWS.Cryptography.MaterialProviders CreateRawAesKeyringInput",
        ],
    },
    "go": {
        "search": ["go"],
        "imports": r"github\.com/aws/aws-(encryption-sdk|cryptographic-material-providers-library)",
        "queries": [
            "aws-encryption-sdk EncryptInput",
            "aws-cryptographic-material-providers-library CreateAwsKmsKeyringInput",
            "aws-cryptographic-material-providers-library CreateRawAesKeyringInput",
        ],
    },
    "rust": {
        "search": ["rust"],
        "imports": r"\baws_esdk\b|\baws_mpl",
        "queries": [
            "aws_esdk encrypt plaintext",
            "aws_mpl_rs create_aws_kms_keyring",
            "aws_mpl_rs create_raw_aes_keyring",
        ],
    },
}


# ---------- call sites ----------

class Site:
    """A place in code where a customer passes options to one API.

    marker is a regex for the start of the call. kind says how the options follow it:
      builder     X.builder().name(arg).name(arg)  (Java, Rust)
      keyword     X(name=arg, ...)  or  new X { Name = arg }  (Python, .NET)
      field       X{Name: arg}  or  new X({ name: arg, name })  (Go, JS)
      positional  call(arg0, arg1)  where members maps an index to a member,
                  or to a {name: member} map for an object literal in that place (JS)
    For builder, keyword and field, members maps option_key(the name in code) to
    the Smithy member.
    """

    def __init__(self, lang, lib, api, marker, kind, members):
        self.lang, self.lib, self.api = lang, lib, api
        self.marker, self.kind, self.members = re.compile(marker), kind, members


def smithy_sites(names):
    """The sites of every API in smithy-names.json, in the code shape that each language generates."""
    sites = []
    for lib, apis in names["libraries"].items():
        for api, entry in apis.items():
            members = {option_key(m): m for m in entry["members"]}
            for alias, m in entry.get("aliases", {}).items():
                members[option_key(alias)] = m
            shape = entry["shape"].split("#")[1]
            snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", re.sub(r"Input$", "", shape)).lower()
            q = re.escape(shape)
            sites += [
                Site("java", lib, api, rf"\b{q}\s*\.\s*builder\s*\(\s*\)", "builder", members),
                Site("python", lib, api, rf"\b{q}\s*\(", "keyword", members),
                Site("dotnet", lib, api, rf"\bnew\s+{q}\s*(\(\s*\))?\s*\{{", "keyword", members),
                Site("go", lib, api, rf"\b{q}\s*\{{", "field", members),
                Site("rust", lib, api, rf"\b{q}\s*::\s*builder\s*\(\s*\)", "builder", members),
            ]
            # The Rust client operation for a Create<Type> input: mpl.create_aws_kms_keyring().
            if snake.startswith("create_"):
                sites.append(Site("rust", lib, api, rf"\.\s*{snake}\s*\(\s*\)", "builder", members))
            for op in entry.get("operations", []):
                sites.append(Site("rust", lib, api, rf"\.\s*{op.lower()}\s*\(\s*\)", "builder", members))
    return sites


def k(**names):
    """{option_key(name in code): Smithy member}."""
    return {option_key(code): member for code, member in names.items()}


# Calls whose names are not the Smithy names: the hand-written Java, Python and
# JS ESDKs, and the Python and JS keyrings and master key providers. A master
# key provider is the older form of a keyring, so its key IDs count as the
# keyring's.
HAND_WRITTEN = [
    Site("java", "esdk", "encrypt", r"\.\s*encryptData\s*\(", "positional", {1: "plaintext", 2: "encryptionContext"}),
    Site("java", "esdk", "decrypt", r"\.\s*decryptData\s*\(", "positional", {1: "ciphertext"}),
    Site("java", "esdk", "client", r"\bAwsCrypto\s*\.\s*builder\s*\(\s*\)", "builder",
         k(withCommitmentPolicy="commitmentPolicy", withMaxEncryptedDataKeys="maxEncryptedDataKeys")),
    Site("python", "esdk", "encrypt", r"\.\s*encrypt\s*\(", "keyword",
         k(source="plaintext", encryption_context="encryptionContext", keyring="keyring",
           materials_manager="materialsManager", frame_length="frameLength", algorithm="algorithmSuiteId")),
    Site("python", "esdk", "decrypt", r"\.\s*decrypt\s*\(", "keyword",
         k(source="ciphertext", encryption_context="encryptionContext", keyring="keyring",
           materials_manager="materialsManager")),
    Site("python", "esdk", "client", r"\bEncryptionSDKClient\s*\(", "keyword",
         k(commitment_policy="commitmentPolicy", max_encrypted_data_keys="maxEncryptedDataKeys")),
    Site("python", "mpl", "aws-kms-multi-keyring", r"\b(Strict|Discovery)?AwsKmsMasterKeyProvider\s*\(", "keyword",
         k(key_ids="kmsKeyIds")),
    Site("javascript", "esdk", "encrypt", r"\bencrypt\s*\(", "positional",
         {1: "plaintext", 2: k(encryptionContext="encryptionContext", frameLength="frameLength",
                               suiteId="algorithmSuiteId")}),
    Site("javascript", "esdk", "decrypt", r"\bdecrypt\s*\(", "positional", {1: "ciphertext"}),
    Site("javascript", "esdk", "client", r"\bbuildClient\s*\(", "positional", {0: "commitmentPolicy"}),
    Site("javascript", "mpl", "aws-kms-multi-keyring", r"\bnew\s+KmsKeyring(Node|Browser)\s*\(\s*\{", "field",
         k(generatorKeyId="generator", keyIds="kmsKeyIds", grantTokens="grantTokens")),
    Site("javascript", "mpl", "raw-aes-keyring", r"\bnew\s+RawAesKeyring(Node|WebCrypto)\s*\(\s*\{", "field",
         k(keyName="keyName", keyNamespace="keyNamespace", unencryptedMasterKey="wrappingKey",
           wrappingSuite="wrappingAlg")),
    Site("javascript", "mpl", "raw-rsa-keyring", r"\bnew\s+RawRsaKeyring(Node|WebCrypto)\s*\(\s*\{", "field",
         k(keyName="keyName", keyNamespace="keyNamespace", padding="paddingScheme")),
]


# ---------- reading code ----------

OPEN, CLOSE = "([{", ")]}"


def _skip(code, i, lang):
    """The index after a string or comment that starts at i, or i when none starts there."""
    two = code[i:i + 2]
    if two == "//" or (lang == "python" and code[i] == "#"):
        end = code.find("\n", i)
        return len(code) if end < 0 else end
    if two == "/*":
        end = code.find("*/", i + 2)
        return len(code) if end < 0 else end + 2
    q = code[i]
    # A Rust ' is a lifetime ('a) unless it closes a one-character literal.
    if q == "'" and lang == "rust" and not re.match(r"'(\\.|[^\\'])'", code[i:i + 4]):
        return i
    if q in "\"'`":
        if lang == "python" and code[i:i + 3] in ('"""', "'''"):
            end = code.find(code[i:i + 3], i + 3)
            return len(code) if end < 0 else end + 3
        j = i + 1
        while j < len(code) and code[j] != q:
            j += 2 if code[j] == "\\" else 1
        return j + 1
    return i


def parts(code, open_at, lang):
    """Split the bracket that opens at open_at into its top-level comma-separated parts.

    Returns (index after the closing bracket, [(start, end)] of each part, not stripped).
    """
    depth, start, out, i = 0, open_at + 1, [], open_at
    while i < len(code):
        j = _skip(code, i, lang)
        if j != i:
            i = j
            continue
        c = code[i]
        if c in OPEN:
            depth += 1
        elif c in CLOSE:
            depth -= 1
            if depth == 0:
                if code[start:i].strip():
                    out.append((start, i))
                return i + 1, out
        elif c == "," and depth == 1:
            out.append((start, i))
            start = i + 1
        i += 1
    return len(code), out


def _space(code, i, lang):
    """The index of the next character that is not space or a comment."""
    while i < len(code):
        if code[i].isspace():
            i += 1
            continue
        j = _skip(code, i, lang)
        if j == i or code[i] in "\"'`":
            return i
        i = j
    return i


def _arg(code, span, lang):
    """(text, start) of one part, without the space and comments before it or the space after it."""
    start = _space(code, span[0], lang)
    return code[start:span[1]].rstrip(), start


def _named(code, span, sep, lang):
    """(name, value, value start) of a `name = value` or `name: value` part, or None."""
    text, start = _arg(code, span, lang)
    m = re.match(rf"(\w+)\s*{sep}\s*", text)
    if m and not text[m.end():].startswith("="):
        return m.group(1), text[m.end():], start + m.end()
    return None


def args(code, site, lang):
    """Each option argument at this site: [(member, argument text, argument offset)]."""
    out = []
    for m in site.marker.finditer(code):
        if site.kind == "builder":
            i = m.end()
            # One chained .name(...) per step. A step with no brackets (.await) or a ? goes on.
            while True:
                i = _space(code, i, lang)
                if code.startswith("?", i):
                    i += 1
                    continue
                step = re.compile(r"\.\s*(\w+)\s*").match(code, i)
                if not step:
                    break
                i = step.end()
                if not code.startswith("(", i):
                    continue
                i, spans = parts(code, i, lang)
                member = site.members.get(option_key(step.group(1)))
                if member and spans:
                    out.append((member, *_arg(code, spans[0], lang)))
            continue
        _, spans = parts(code, m.end() - 1, lang)
        if site.kind == "positional":
            for index, member in site.members.items():
                if index >= len(spans):
                    continue
                text, start = _arg(code, spans[index], lang)
                if isinstance(member, dict):
                    if text.startswith("{"):
                        out += _fields(code, start, member, ":", lang)
                else:
                    out.append((member, text, start))
        else:
            out += _fields(code, m.end() - 1, site.members, "=" if site.kind == "keyword" else ":", lang)
    return out


def _fields(code, open_at, members, sep, lang):
    """The named options inside the bracket at open_at. A field with no value ({ keyIds }) passes a variable of that name."""
    out = []
    for span in parts(code, open_at, lang)[1]:
        named = _named(code, span, sep, lang)
        if named:
            name, value, start = named
        elif sep == ":" and re.fullmatch(r"\w+", _arg(code, span, lang)[0]):
            value, start = _arg(code, span, lang)
            name = value
        else:
            continue
        member = members.get(option_key(name))
        if member:
            out.append((member, value, start))
    return out


# ---------- conversions ----------

class Rule:
    """One conversion. from_ is what the customer had before it, in the page's have words."""

    def __init__(self, label, pattern, from_, langs=None, unless=None):
        self.label, self.pattern, self.from_ = label, re.compile(pattern), from_
        self.langs = set(langs) if langs else None
        self.unless = re.compile(unless) if unless else None

    def matches(self, text, lang):
        if self.langs and lang not in self.langs:
            return False
        return bool(self.pattern.search(text)) and not (self.unless and self.unless.search(text))


STRING, FILE, BASE64, HEX, CONFIG = "a string", "a file", "base64 text", "hex text", "a string from your config"
BASE64_JS = r"Buffer\.from\s*\([^)]*['\"]base64['\"]"
RULES = [
    Rule(".getBytes(...)", r"\.getBytes\s*\(", STRING, ["java"]),
    Rule(".encode()", r"\.encode\s*\(", STRING, ["python"], unless=r"b64encode|\.encode\s*\(\s*['\"](base64|hex)"),
    Rule("bytes(..., encoding)", r"\bbytes\s*\([^()]*,\s*(encoding\s*=\s*)?['\"]utf", STRING, ["python"]),
    Rule("b\"...\" literal", r"(?<![\w\"'])b['\"]", STRING, ["python", "rust"]),
    Rule("Buffer.from(...)", r"Buffer\.from\s*\(", STRING, ["javascript"], unless=BASE64_JS),
    Rule("TextEncoder.encode", r"TextEncoder\s*\(\s*\)\s*\.\s*encode\s*\(|\bencoder\.encode\s*\(", STRING, ["javascript"]),
    Rule(".as_bytes()", r"\.as_bytes\s*\(\s*\)", STRING, ["rust"]),
    Rule(".into_bytes()", r"\.into_bytes\s*\(\s*\)", STRING, ["rust"]),
    Rule("[]byte(...)", r"\[\]byte\s*\(", STRING, ["go"]),
    Rule("Encoding.UTF8.GetBytes", r"Encoding\.(UTF8|ASCII|Unicode)\.GetBytes\s*\(", STRING, ["dotnet"]),
    Rule("string literal", r"^\s*(@|f|r)?(\"[^\"]*\"|'[^']*'|`[^`$]*`)\s*$", STRING),
    Rule("Files.readAllBytes", r"Files\.readAllBytes\s*\(", FILE, ["java"]),
    Rule(".read()", r"\.read\s*\(\s*\)", "a file or stream", ["python"]),
    Rule("fs.readFileSync", r"\breadFile(Sync)?\s*\(", FILE, ["javascript"]),
    Rule("fs::read", r"\bfs::read(_to_string)?\s*\(", FILE, ["rust"]),
    Rule("File.ReadAllBytes", r"File\.ReadAll(Bytes|Text)\s*\(", FILE, ["dotnet"]),
    Rule("os.ReadFile", r"\b(os|ioutil)\.ReadFile\s*\(", FILE, ["go"]),
    Rule("base64 decode", r"Base64\.(getDecoder|getMimeDecoder|decode)|b64decode\s*\(|" + BASE64_JS
         + r"|FromBase64String|base64\.\w*Encoding\.DecodeString|STANDARD\.decode|base64::decode", BASE64),
    Rule("hex decode", r"bytes\.fromhex|Hex\.decode|hex::decode|hex\.DecodeString|FromHexString|\.unhexlify\s*\(", HEX),
    Rule("environment variable", r"getenv\s*\(|os\.environ|process\.env\.|env::var\s*\(|GetEnvironmentVariable\s*\(|os\.Getenv\s*\(", CONFIG),
    Rule("ByteBuffer.wrap", r"ByteBuffer\.wrap\s*\(", "a byte array", ["java"]),
    Rule("new MemoryStream(...)", r"new\s+MemoryStream\s*\(", "a byte array", ["dotnet"]),
    Rule(".to_vec()", r"\.to_vec\s*\(\s*\)", "a byte slice", ["rust"]),
    Rule("Some(x.into())", r"Some\s*\(.*\.into\s*\(\s*\)\s*\)", "a value that converts with into()", ["rust"]),
    Rule(".to_string()", r"\.to_(string|owned)\s*\(\s*\)|String::from\s*\(", "a &str", ["rust"]),
    Rule("str(...)", r"(?<![\w.])str\s*\(", "a value that is not a string", ["python"]),
    Rule(".toString()", r"\.toString\s*\(\s*\)|String\.valueOf\s*\(", "a value that is not a string", ["java", "javascript"]),
    Rule("list literal", r"^\s*\[", "separate values", ["python", "javascript"]),
    Rule("list of one", r"Collections\.singletonList|List\.of\s*\(|Arrays\.asList", "separate values", ["java"]),
    Rule("map literal", r"Collections\.singletonMap|Map\.of\s*\(|ImmutableMap\.of", "key/value pairs", ["java"]),
]
AS_IS = "passed as is"


def _assignment(lines, name):
    """The right-hand side of the last line in lines that assigns name, or None."""
    pattern = re.compile(rf"(?<![\w.]){re.escape(name)}\s*(:[^=]*)?(:=|=)(?!=)\s*(.+)")
    for line in reversed(lines):
        m = pattern.search(line)
        if m:
            return m.group(3)
    return None


def classify(arg, before, lang):
    """The rules that the argument matches, or that the line before it which assigns its variable matches.

    before is the lines above the call, nearest last. An argument that matches
    no rule gets [AS_IS].
    """
    hits = [r for r in RULES if r.matches(arg, lang)]
    var = re.fullmatch(r"[&*]?(mut\s+)?(\w+)(\.clone\(\))?", arg)
    if not hits and var:
        rhs = _assignment(before, var.group(2))
        if rhs is not None:
            hits = [r for r in RULES if r.matches(rhs.rstrip(";, "), lang)]
    return hits or [AS_IS]


# ---------- searching ----------

def token():
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        if os.environ.get(name):
            return os.environ[name]
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        sys.exit("code search needs a token: set GH_TOKEN or GITHUB_TOKEN, or run gh auth login")


def get(url, auth):
    """GET a GitHub API URL as JSON. Waits out the rate limit, which allows 10 code searches a minute."""
    for _ in range(10):
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {auth}",
                                                   "Accept": "application/vnd.github+json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code not in (403, 429):
                raise
            body = e.read().decode(errors="replace")
            limited = e.code == 429 or "rate limit" in body.lower() or e.headers.get("x-ratelimit-remaining") == "0"
            if not limited:
                raise SystemExit(f"GitHub refused {url}: {e.code} {body}")
            # A secondary limit says {"message": "try again in 187.2s"} and may send no headers.
            later = re.search(r"try again in ([\d.]+)s", body)
            reset = int(e.headers.get("x-ratelimit-reset", time.time() + 60))
            wait = int(e.headers.get("retry-after") or (later and float(later.group(1))) or max(reset - time.time(), 1)) + 1
            print(f"rate limited; waiting {wait}s", file=sys.stderr)
            time.sleep(wait)
    raise SystemExit(f"still rate limited after 10 waits: {url}")


def is_customer(item):
    repo = item["repository"]
    return (repo["owner"]["login"].lower() not in AWS_OWNERS and not repo["fork"] and not repo["private"]
            and not SKIP_PATH.search(item["path"]) and not LIBRARY_COPY.search(item["path"]))


def search(auth, lang, max_pages):
    """{(repo, path): (commit, html url)} of every customer file that a search for this language finds."""
    files = {}
    spec = LANGUAGES[lang]
    for query in spec["queries"]:
        for search_lang in spec["search"]:
            q = f"{query} language:{search_lang}"
            for page in range(1, max_pages + 1):
                url = f"{API}/search/code?" + urllib.parse.urlencode({"q": q, "per_page": PAGE_SIZE, "page": page})
                items = get(url, auth)["items"]
                for item in filter(is_customer, items):
                    commit = urllib.parse.parse_qs(urllib.parse.urlparse(item["url"]).query)["ref"][0]
                    files[(item["repository"]["full_name"], item["path"])] = commit
                if len(items) < PAGE_SIZE:
                    break
    return files


def fetch(repo, commit, path):
    """A public file's text, or None. raw.githubusercontent.com does not count against the API rate limit."""
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{urllib.parse.quote(path)}"
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        print(f"skipping {repo}/{path}: {e}", file=sys.stderr)
        return None


# ---------- usage.json ----------

def calls(code, lang, sites):
    """Every option argument in one file: [(lib, api, option key, conversion, line)]."""
    if not re.search(LANGUAGES[lang]["imports"], code):
        return []
    lines = code.split("\n")
    out = []
    for site in sites:
        if site.lang != lang:
            continue
        for member, arg, at in args(code, site, lang):
            line = code.count("\n", 0, at)
            for conv in classify(arg, lines[max(0, line - LOOKBACK):line], lang):
                out.append((site.lib, site.api, option_key(member), conv, line + 1))
    return out


def add(apis, lang, repo, path, commit, hit):
    lib, api, option, conv, line = hit
    label, from_ = (AS_IS, None) if conv == AS_IS else (conv.label, conv.from_)
    convs = apis.setdefault(f"{lib}|{api}", {}).setdefault(option, {})
    c = convs.setdefault(label, {"conversion": label, "from": from_, "count": 0, "languages": {}, "examples": []})
    c["count"] += 1
    c["languages"][lang] = c["languages"].get(lang, 0) + 1
    # Examples from different repos show more ways of reaching the call.
    if len(c["examples"]) < MAX_EXAMPLES and all(e["repo"] != repo for e in c["examples"]):
        c["examples"].append({"repo": repo, "path": path, "line": line, "language": lang,
                              "url": f"https://github.com/{repo}/blob/{commit}/{urllib.parse.quote(path)}#L{line}"})


def ranked(apis):
    """{api: {option: [conversion, most calls first]}}."""
    return {api: {opt: sorted(convs.values(), key=lambda c: (-c["count"], c["conversion"]))
                  for opt, convs in sorted(options.items())}
            for api, options in sorted(apis.items())}


def main(argv=None):
    here = Path(__file__).resolve().parent
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--names", default=str(here / "smithy-names.json"))
    p.add_argument("--out", default=str(here.parent / "dashboard" / "api-examples" / "usage.json"))
    p.add_argument("--max-pages", type=int, default=10, help="pages of 100 results per search (at most 10)")
    a = p.parse_args(argv)

    sites = smithy_sites(json.loads(Path(a.names).read_text())) + HAND_WRITTEN
    auth = token()
    apis, languages = {}, {}
    for lang in LANGUAGES:
        files = search(auth, lang, min(a.max_pages, 10))
        n_calls, repos = 0, set()
        for (repo, path), commit in sorted(files.items()):
            code = fetch(repo, commit, path)
            for hit in calls(code or "", lang, sites):
                add(apis, lang, repo, path, commit, hit)
                n_calls += 1
                repos.add(repo)
        languages[lang] = {"files": len(files), "repos": len(repos), "calls": n_calls}
        print(f"{lang}: {len(files)} files, {len(repos)} repos with calls, {n_calls} option arguments", file=sys.stderr)

    out = {
        "generated_by": "api-examples/usage_search.py",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "excluded_owners": sorted(AWS_OWNERS),
        "languages": languages,
        "apis": ranked(apis),
    }
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
