#!/usr/bin/env python3
"""Write example calls for Java, Python, .NET, Go and JavaScript, for the types page.

  other_languages.py --shipped <folder with the api-examples-*-shipped artifacts> [--out types-others.json]

None of this code is compiled. Each call starts from a released library's own signature, from the
artifacts that api-examples-shipped.yml uploads. Every API and option in them shows, so a new keyring
in a release shows on the next run. For each value a customer may hold, it picks the cheapest
conversion to a type the library takes. The held values and conversions are written by hand, like
the Rust types list, so the page marks these calls as not compiled.
"""
import argparse
import json
import re
from pathlib import Path

import calls

OUT = Path(__file__).resolve().parent.parent.parent / "dashboard" / "api-examples" / "types-others.json"

# An option takes the kinds of held value that pass to it as is. It also shows these, which customers
# often convert: text, base64 text or a file for bytes, and so on.
MORE_KINDS = {"bytes": ["text", "base64 text", "file / stream"], "map": ["pairs"], "list": ["text"],
              "the type itself": ["what builds it"]}
# A number option with one of these words in its name is a span of time, so it is handed a duration too.
TIME = re.compile(r"ttl|seconds|duration|interval|period|timeout", re.I)

# For each language: held value -> (kind, [(type the library takes, conversion)]).
# A conversion is code using x, or (setup lines, value) when it needs statements first. A pair uses k and v.
# A conversion's cost is its number of calls (calls.py). When two conversions cost the same, the first wins.
# What each held type is, in plain words, and its docs page. The page shows this when someone clicks a type.
JAVA = "https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/"
JLS = "https://docs.oracle.com/javase/specs/jls/se17/html/"
PY = "https://docs.python.org/3/library/"
NET = "https://learn.microsoft.com/en-us/dotnet/"
GO = "https://go.dev/ref/spec#"
MDN = "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/"
ABOUT = {
    "java": {
        "byte[]": ("An array of bytes.", JLS + "jls-10.html"),
        "ByteBuffer": ("Bytes in a buffer that keeps track of where you are reading.", JAVA + "nio/ByteBuffer.html"),
        "String": ("Text. It can't be changed.", JAVA + "lang/String.html"),
        "String (base64)": ("Text that holds bytes written as base64, like a stored ciphertext.",
                            JAVA + "util/Base64.html"),
        "Path": ("A file path.", JAVA + "nio/file/Path.html"),
        "InputStream": ("Bytes you read one piece at a time, like an open file.", JAVA + "io/InputStream.html"),
        "Map<String, String>": ("A lookup table from text keys to text values.", JAVA + "util/Map.html"),
        "(String, String)": ("Two strings, like one key and one value. Java has no pair type, so they are two "
                             "variables.", None),
        "List<String>": ("A list of strings.", JAVA + "util/List.html"),
        "String[]": ("An array of strings.", JLS + "jls-10.html"),
        "int": ("A whole number from -2^31 to 2^31 - 1.", JLS + "jls-4.html#jls-4.2.1"),
        "long": ("A whole number from -2^63 to 2^63 - 1.", JLS + "jls-4.html#jls-4.2.1"),
        "Duration": ("A span of time, like 5 seconds.", JAVA + "time/Duration.html"),
        "KmsClient": ("The AWS SDK for Java client for AWS KMS.",
                      "https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/services/kms/KmsClient.html"),
        "Region": ("An AWS Region, like us-west-2.",
                   "https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/regions/Region.html"),
    },
    "python": {
        "bytes": ("Bytes. They can't be changed.", PY + "stdtypes.html#bytes"),
        "bytearray": ("Bytes that can be changed.", PY + "stdtypes.html#bytearray"),
        "str": ("Text.", PY + "stdtypes.html#text-sequence-type-str"),
        "str (base64)": ("Text that holds bytes written as base64, like a stored ciphertext.", PY + "base64.html"),
        "pathlib.Path": ("A file path.", PY + "pathlib.html"),
        "BinaryIO": ("An open file, or another stream of bytes.", PY + "typing.html#typing.BinaryIO"),
        "dict": ("A lookup table from keys to values.", PY + "stdtypes.html#dict"),
        "(str, str)": ("Two strings, like one key and one value.", PY + "stdtypes.html#tuple"),
        "list[str]": ("A list of strings.", PY + "stdtypes.html#list"),
        "tuple[str, ...]": ("Strings in a row that can't be changed.", PY + "stdtypes.html#tuple"),
        "int": ("A whole number of any size.", PY + "functions.html#int"),
        "timedelta": ("A span of time, like 5 seconds.", PY + "datetime.html#timedelta-objects"),
        "BaseClient": ("A boto3 client, like boto3.client(\"kms\").",
                       "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms.html"),
        "boto3.Session": ("AWS settings and credentials that make clients.",
                          "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html"),
    },
    "dotnet": {
        "byte[]": ("An array of bytes.", NET + "csharp/language-reference/builtin-types/arrays"),
        "MemoryStream": ("Bytes in memory that you read like a stream.", NET + "api/system.io.memorystream"),
        "string": ("Text. It can't be changed.", NET + "api/system.string"),
        "string (base64)": ("Text that holds bytes written as base64, like a stored ciphertext.",
                            NET + "api/system.convert.frombase64string"),
        "FileInfo": ("A file on disk.", NET + "api/system.io.fileinfo"),
        "Stream": ("Bytes you read one piece at a time, like an open file.", NET + "api/system.io.stream"),
        "Dictionary<string, string>": ("A lookup table from text keys to text values.",
                                       NET + "api/system.collections.generic.dictionary-2"),
        "(string, string)": ("Two strings, like one key and one value.",
                             NET + "csharp/language-reference/builtin-types/value-tuples"),
        "List<string>": ("A list of strings.", NET + "api/system.collections.generic.list-1"),
        "string[]": ("An array of strings.", NET + "csharp/language-reference/builtin-types/arrays"),
        "int": ("A whole number from -2^31 to 2^31 - 1.", NET + "api/system.int32"),
        "long": ("A whole number from -2^63 to 2^63 - 1.", NET + "api/system.int64"),
        "TimeSpan": ("A span of time, like 5 seconds.", NET + "api/system.timespan"),
        "AmazonKeyManagementServiceClient": (
            "The AWS SDK for .NET client for AWS KMS.",
            "https://docs.aws.amazon.com/sdkfornet/v3/apidocs/items/KeyManagementService/TKeyManagementServiceClient.html"),
        "AmazonKeyManagementServiceConfig": (
            "Settings that build a KMS client, like the Region.",
            "https://docs.aws.amazon.com/sdkfornet/v3/apidocs/items/KeyManagementService/TKeyManagementServiceConfig.html"),
    },
    "go": {
        "[]byte": ("A slice of bytes.", GO + "Slice_types"),
        "string": ("Text. It can't be changed.", GO + "String_types"),
        "string (base64)": ("Text that holds bytes written as base64, like a stored ciphertext.",
                            "https://pkg.go.dev/encoding/base64"),
        "string (path)": ("Text that holds a file path.", "https://pkg.go.dev/os#ReadFile"),
        "io.Reader": ("Bytes you read one piece at a time, like an open file.", "https://pkg.go.dev/io#Reader"),
        "map[string]string": ("A lookup table from text keys to text values.", GO + "Map_types"),
        "(string, string)": ("Two strings, like one key and one value. Go has no pair type, so they are two "
                             "variables.", None),
        "[]string": ("A slice of strings.", GO + "Slice_types"),
        "int": ("A whole number, 64 bits on most machines.", GO + "Numeric_types"),
        "int64": ("A whole number from -2^63 to 2^63 - 1.", GO + "Numeric_types"),
        "time.Duration": ("A span of time, like 5 seconds.", "https://pkg.go.dev/time#Duration"),
        "*kms.Client": ("The AWS SDK for Go client for AWS KMS.",
                        "https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/kms#Client"),
        "aws.Config": ("AWS settings that build clients, like the Region and credentials.",
                       "https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws#Config"),
    },
    "javascript": {
        "Uint8Array": ("An array of bytes.", MDN + "Uint8Array"),
        "Buffer": ("Node.js bytes. A Buffer is also a Uint8Array.", "https://nodejs.org/api/buffer.html"),
        "string": ("Text.", MDN + "String"),
        "string (base64)": ("Text that holds bytes written as base64, like a stored ciphertext.",
                            "https://nodejs.org/api/buffer.html#buffers-and-character-encodings"),
        "string (path)": ("Text that holds a file path.", "https://nodejs.org/api/fs.html"),
        "Readable": ("A Node.js stream of bytes you read piece by piece, like an open file.",
                     "https://nodejs.org/api/stream.html#readable-streams"),
        "Record<string, string>": ("An object from text keys to text values.",
                                   "https://www.typescriptlang.org/docs/handbook/utility-types.html#recordkeys-type"),
        "[string, string]": ("Two strings, like one key and one value.",
                             "https://www.typescriptlang.org/docs/handbook/2/objects.html#tuple-types"),
        "string[]": ("An array of strings.", MDN + "Array"),
        "number": ("A number. Whole numbers are exact up to 2^53 - 1.", MDN + "Number"),
        "KMSClient": ("The AWS SDK for JavaScript client for AWS KMS.",
                      "https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/client/kms/"),
        "KMSClientConfig": ("Settings that build a KMS client, like the Region.",
                            "https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/client/kms/"),
    },
}
RETURN_ON_ERROR = "if err != nil { return err }"
HELD = {
    "java": {
        "byte[]": ("bytes", [("byte[]", "x"), ("ByteBuffer", "ByteBuffer.wrap(x)"),
                             ("InputStream", "new ByteArrayInputStream(x)")]),
        "ByteBuffer": ("bytes", [("ByteBuffer", "x"), ("byte[]", "x.array()")]),
        "String": ("text", [("String", "x"), ("byte[]", "x.getBytes(StandardCharsets.UTF_8)"),
                            ("ByteBuffer", "StandardCharsets.UTF_8.encode(x)"), ("List<String>", "List.of(x)")]),
        # decryptString takes a base64 ciphertext.
        "String (base64)": ("base64 text", [("String", "x"), ("byte[]", "Base64.getDecoder().decode(x)"),
                                            ("ByteBuffer", "ByteBuffer.wrap(Base64.getDecoder().decode(x))")]),
        "Path": ("file / stream", [("InputStream", "Files.newInputStream(x)"), ("byte[]", "Files.readAllBytes(x)"),
                                   ("ByteBuffer", "ByteBuffer.wrap(Files.readAllBytes(x))")]),
        "InputStream": ("file / stream", [("InputStream", "x"), ("byte[]", "x.readAllBytes()"),
                                          ("ByteBuffer", "ByteBuffer.wrap(x.readAllBytes())")]),
        "Map<String, String>": ("map", [("Map<String, String>", "x")]),
        "(String, String)": ("pairs", [("Map<String, String>", "Map.of(k, v)")]),
        "List<String>": ("list", [("List<String>", "x")]),
        "String[]": ("list", [("List<String>", "List.of(x)")]),
        "int": ("number", [("int", "x"), ("long", "x")]),
        "long": ("number", [("long", "x"), ("int", "Math.toIntExact(x)")]),
        "Duration": ("Duration", [("long", "x.getSeconds()"), ("int", "Math.toIntExact(x.getSeconds())")]),
        "KmsClient": ("the type itself", [("KmsClient", "x")]),
        "Region": ("what builds it", [("KmsClient", "KmsClient.builder().region(x).build()")]),
    },
    "python": {
        "bytes": ("bytes", [("bytes", "x"), ("bytearray", "bytearray(x)")]),
        "bytearray": ("bytes", [("bytearray", "x"), ("bytes", "bytes(x)")]),
        "str": ("text", [("str", "x"), ("bytes", "x.encode()"), ("list[str]", "[x]")]),
        "str (base64)": ("base64 text", [("bytes", "base64.b64decode(x)")]),
        "pathlib.Path": ("file / stream", [("IOBase", 'open(x, "rb")'), ("bytes", "x.read_bytes()")]),
        "BinaryIO": ("file / stream", [("IOBase", "x"), ("bytes", "x.read()")]),
        "dict": ("map", [("dict", "x")]),
        "(str, str)": ("pairs", [("dict", "{k: v}")]),
        "list[str]": ("list", [("list[str]", "x")]),
        "tuple[str, ...]": ("list", [("list[str]", "list(x)")]),
        "int": ("number", [("int", "x"), ("positive int", "x")]),
        "timedelta": ("Duration", [("int", "int(x.total_seconds())")]),
        "BaseClient": ("the type itself", [("BaseClient", "x")]),
        "boto3.Session": ("what builds it", [("BaseClient", 'x.client("kms")')]),
    },
    "dotnet": {
        "byte[]": ("bytes", [("MemoryStream", "new MemoryStream(x)")]),
        "MemoryStream": ("bytes", [("MemoryStream", "x")]),
        "string": ("text", [("String", "x"), ("MemoryStream", "new MemoryStream(Encoding.UTF8.GetBytes(x))"),
                            ("List<String>", "new List<string> { x }")]),
        "string (base64)": ("base64 text", [("MemoryStream", "new MemoryStream(Convert.FromBase64String(x))")]),
        "FileInfo": ("file / stream", [("MemoryStream", "new MemoryStream(File.ReadAllBytes(x.FullName))")]),
        "Stream": ("file / stream", [("MemoryStream", (["var copy = new MemoryStream();", "x.CopyTo(copy);"], "copy"))]),
        "Dictionary<string, string>": ("map", [("Dictionary<String, String>", "x")]),
        "(string, string)": ("pairs", [("Dictionary<String, String>", "new Dictionary<string, string> { [k] = v }")]),
        "List<string>": ("list", [("List<String>", "x")]),
        "string[]": ("list", [("List<String>", "x.ToList()")]),
        "int": ("number", [("Int64", "x")]),
        "long": ("number", [("Int64", "x")]),
        "TimeSpan": ("Duration", [("Int64", "(long)x.TotalSeconds")]),
        "AmazonKeyManagementServiceClient": ("the type itself", [("IAmazonKeyManagementService", "x")]),
        "AmazonKeyManagementServiceConfig": ("what builds it",
                                             [("IAmazonKeyManagementService", "new AmazonKeyManagementServiceClient(x)")]),
    },
    "go": {
        "[]byte": ("bytes", [("[]byte", "x")]),
        "string": ("text", [("string", "x"), ("*string", "&x"), ("[]byte", "[]byte(x)"), ("[]string", "[]string{x}")]),
        "string (base64)": ("base64 text", [("[]byte", (["data, err := base64.StdEncoding.DecodeString(x)",
                                                         RETURN_ON_ERROR], "data"))]),
        "string (path)": ("file / stream", [("[]byte", (["data, err := os.ReadFile(x)", RETURN_ON_ERROR], "data"))]),
        "io.Reader": ("file / stream", [("[]byte", (["data, err := io.ReadAll(x)", RETURN_ON_ERROR], "data"))]),
        "map[string]string": ("map", [("map[string]string", "x")]),
        "(string, string)": ("pairs", [("map[string]string", "map[string]string{k: v}")]),
        "[]string": ("list", [("[]string", "x")]),
        "int": ("number", [("int64", "int64(x)"), ("*int64", "aws.Int64(int64(x))")]),
        "int64": ("number", [("int64", "x"), ("*int64", "&x")]),
        "time.Duration": ("Duration", [("int64", "int64(x.Seconds())"), ("*int64", "aws.Int64(int64(x.Seconds()))")]),
        "*kms.Client": ("the type itself", [("Client", "x")]),
        "aws.Config": ("what builds it", [("Client", "kms.NewFromConfig(x)")]),
    },
    "javascript": {
        "Uint8Array": ("bytes", [("Uint8Array", "x"), ("Buffer", "Buffer.from(x)")]),
        "Buffer": ("bytes", [("Buffer", "x"), ("Uint8Array", "x")]),
        "string": ("text", [("string", "x"), ("Uint8Array", "new TextEncoder().encode(x)"), ("string[]", "[x]")]),
        "string (base64)": ("base64 text", [("Buffer", 'Buffer.from(x, "base64")'),
                                            ("Uint8Array", 'Buffer.from(x, "base64")')]),
        "string (path)": ("file / stream", [("Readable", "fs.createReadStream(x)"), ("Buffer", "fs.readFileSync(x)"),
                                            ("Uint8Array", "fs.readFileSync(x)")]),
        "Readable": ("file / stream", [("Readable", "x"), ("Buffer", "Buffer.concat(await x.toArray())"),
                                       ("Uint8Array", "Buffer.concat(await x.toArray())")]),
        "Record<string, string>": ("map", [("EncryptionContext", "x")]),
        "[string, string]": ("pairs", [("EncryptionContext", "{ [k]: v }")]),
        "string[]": ("list", [("string[]", "x")]),
        "number": ("number", [("number", "x")]),
        "KMSClient": ("the type itself", [("KmsClientSupplier<AwsEsdkKMSInterface>", "() => x")]),
        "KMSClientConfig": ("what builds it", [("KmsClientSupplier<AwsEsdkKMSInterface>", "getClient(KMS, x)")]),
    },
}


def short_type(t):
    t = t.replace("java.lang.", "").replace("java.util.", "")
    return t if "<" in t else t.split(".")[-1]


def split_params(text):
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(text[start:i].strip())
            start = i + 1
    return parts + [text[start:].strip()] if text.strip() else parts


def template(lang, signature, taken):
    """The call in a released signature, with {x} where the argument goes."""
    if lang == "java":
        head, params = signature[:signature.rindex("(")], signature[signature.rindex("(") + 1:-1]
        args = []
        for param in split_params(params):
            ty, _, name = param.rpartition(" ") if " " in param.replace(", ", ",") else (param, "", "")
            args.append("{x}" if short_type(ty or param) == taken or not name else name)
        return f"{head}({', '.join(args)})"
    if lang == "javascript":
        # The released client is used as encrypt(keyring, plaintext, options) and decrypt(keyring, ciphertext).
        m = re.fullmatch(r"client\.(encrypt|decrypt)\((\w+): .+\)", signature)
        if m:
            return f"{m.group(1)}(keyring, {{x}})"
        m = re.fullmatch(r"client\.(encrypt|decrypt)\(\{ (\w+): .+ \}\)", signature)
        if m:
            data = "plaintext" if m.group(1) == "encrypt" else "ciphertext"
            return f"{m.group(1)}(keyring, {data}, {{ {m.group(2)}: {{x}} }})"
        return re.sub(r"\{ (\w+): .+ \}", r"{ \1: {x} }", signature)
    if lang == "python":
        return re.sub(r"\((\w+)=.+\)", r"(\1={x})", signature)
    if lang == "dotnet":
        return re.sub(r"\{ (\w+) = .+ \}", r"{ \1 = {x} }", signature)
    return re.sub(r"\{(\w+): .+\}", r"{\1: {x}}", signature)


def rows_for(key, lang, takes):
    """The rows of one option in one language. takes maps each type the library takes to its call."""
    held = HELD[lang]
    as_is = {kind for kind, conversions in held.values() for t, c in conversions if t in takes and c == "x"}
    kinds = set(as_is) | {k for kind in as_is for k in MORE_KINDS.get(kind, [])}
    if "number" in kinds and TIME.search(key.split("|")[-1]):
        kinds.add("Duration")
    rows = []
    for label, (kind, conversions) in held.items():
        if kind not in kinds:
            continue
        best = None
        for taken, conversion in conversions:
            setup, value = conversion if isinstance(conversion, tuple) else ([], conversion)
            cost = calls.count("\n".join(setup + [value]))
            if taken in takes and (best is None or cost < best[0]):
                best = (cost, "\n".join(setup + [takes[taken].replace("{x}", value)]))
        cost, code = best if best else (None, "")
        rows.append({"type": label, "calls": cost, "code": code, "kind": kind})
    # A type that no held value passes as is, like a keyring interface, shows as itself.
    covered = {t for _, conversions in held.values() for t, c in conversions if c == "x"}
    for taken, call in takes.items():
        if taken not in covered:
            rows.append({"type": taken, "calls": 0, "code": call.replace("{x}", "x"), "kind": "the type itself"})
    return sorted(rows, key=lambda r: (r["calls"] is None, r["calls"] or 0, r["type"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--shipped", required=True)
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()
    # Each API and option, keyed like the Rust ones: library, API and Smithy member.
    apis, templates, shipped = {}, {}, {}
    for path in sorted(Path(args.shipped).glob("*/*.json")):
        artifact = json.loads(path.read_text())
        lang, lib = artifact["language"], artifact["library"]
        shipped.setdefault(lang, {})[lib] = artifact.get("shipped")
        for api in artifact["apis"]:
            entry = apis.setdefault((lib, api["id"]), {"lib": lib, "id": api["id"], "name": api["name"],
                                                       "group": api.get("group", ""), "options": {}})
            for way in api["ways"]:
                row = way.get("row") or ""
                if way["kind"] != "setter" or row in ("", "construct"):
                    continue
                member = row.removeprefix("extra:")
                key = f"{lib}|{api['id']}|{member}"
                opt = entry["options"].setdefault(key, {"key": key, "name": member, "names": {}, "takes": {}})
                opt["names"].setdefault(lang, way.get("option") or way["id"])
                found = templates.setdefault((key, lang), {})
                for taken in way.get("takes", []):
                    t = short_type(taken["type"])
                    found.setdefault(t, template(lang, taken["signature"], t))
                opt["takes"][lang] = " | ".join(found)
    rows = {}
    for (key, lang), takes in sorted(templates.items()):
        if lang in HELD and takes:
            rows.setdefault(key, {})[lang] = rows_for(key, lang, takes)
    about = {lang: {label: {"parts": [{"name": label, "text": ABOUT[lang][label][0], "url": ABOUT[lang][label][1]}]}
                    for label in held} for lang, held in HELD.items()}
    out = {
        "generated_by": "api-examples/types/other_languages.py",
        "note": ("Java, Python, .NET, Go, JS: calls written from each release's signatures, not compiled. "
                 "api-examples/types/other_languages.py writes them."),
        "shipped": shipped,
        "apis": [{**a, "options": list(a["options"].values())} for a in apis.values()],
        "rows": rows,
        "about": about,
    }
    args.out.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {sum(len(r) for langs in rows.values() for r in langs.values())} rows for "
          f"{sum(len(a['options']) for a in apis.values())} options in {len(apis)} APIs")


if __name__ == "__main__":
    main()
