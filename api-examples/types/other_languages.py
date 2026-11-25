#!/usr/bin/env python3
"""Write example calls for Java, Python, .NET, Go and JavaScript into the dashboard page data.

  other_languages.py --shipped <folder with the api-examples-*-shipped artifacts>

None of this code is compiled. Each call starts from a released library's own signature, from the
artifacts that api-examples-shipped.yml uploads. For each value a customer may hold, it picks the
cheapest conversion to a type the library takes. The held values and conversions are written by hand,
so the page marks these calls as not compiled.
"""
import argparse
import json
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parent.parent.parent / "dashboard" / "api-examples" / "types.json"

BYTES = ["bytes", "text", "file / stream"]
# Page key -> the shipped artifact's API and row, and the kinds of held values to try.
OPTIONS = {
    "mpl/RawAesKeyring.wrapping_key": ("raw-aes-keyring", "wrappingKey", BYTES + ["base64 text"]),
    "mpl/RawAesKeyring.key_name": ("raw-aes-keyring", "keyName", ["text"]),
    "mpl/AwsKmsKeyring.kms_key_id": ("aws-kms-keyring", "kmsKeyId", ["text"]),
    "mpl/AwsKmsKeyring.kms_client": ("aws-kms-keyring", "kmsClient", ["the type itself", "what builds it"]),
    "mpl/AwsKmsKeyring.grant_tokens": ("aws-kms-keyring", "grantTokens", ["list", "text"]),
    "mpl/HierarchicalKeyring.ttl": ("hierarchical-keyring", "ttlSeconds", ["Duration", "number"]),
    "mpl/HierarchicalKeyring.branch_key_id": ("hierarchical-keyring", "branchKeyId", ["text"]),
    "esdk/encrypt.plaintext": ("encrypt", "plaintext", BYTES),
    "esdk/decrypt.ciphertext": ("decrypt", "ciphertext", BYTES + ["base64 text"]),
    "esdk/encrypt.encryption_context": ("encrypt", "encryptionContext", ["map", "pairs"]),
    "esdk/encrypt.frame_length": ("encrypt", "frameLength", ["number"]),
    "esdk/Client.max_encrypted_data_keys": ("client", "maxEncryptedDataKeys", ["number"]),
}

# For each language: held value -> (kind, [(type the library takes, cost, conversion)]).
# Cost 0 passes the value as is, 1 adds & or a pointer, 2 adds one call, 3 adds a few, 4 or more is real work.
# A conversion is code using x, or (setup lines, value) when it needs statements first.
# A pair uses k and v.
RETURN_ON_ERROR = "if err != nil { return err }"
HELD = {
    "java": {
        "byte[]": ("bytes", [("byte[]", 0, "x"), ("ByteBuffer", 2, "ByteBuffer.wrap(x)"),
                             ("InputStream", 2, "new ByteArrayInputStream(x)")]),
        "ByteBuffer": ("bytes", [("ByteBuffer", 0, "x"), ("byte[]", 2, "x.array()")]),
        "String": ("text", [("String", 0, "x"), ("byte[]", 2, "x.getBytes(StandardCharsets.UTF_8)"),
                            ("ByteBuffer", 2, "StandardCharsets.UTF_8.encode(x)"), ("List<String>", 2, "List.of(x)")]),
        # decryptString takes a base64 ciphertext.
        "String (base64)": ("base64 text", [("String", 0, "x"), ("byte[]", 2, "Base64.getDecoder().decode(x)"),
                                            ("ByteBuffer", 3, "ByteBuffer.wrap(Base64.getDecoder().decode(x))")]),
        "Path": ("file / stream", [("InputStream", 2, "Files.newInputStream(x)"), ("byte[]", 3, "Files.readAllBytes(x)"),
                                   ("ByteBuffer", 3, "ByteBuffer.wrap(Files.readAllBytes(x))")]),
        "InputStream": ("file / stream", [("InputStream", 0, "x"), ("byte[]", 2, "x.readAllBytes()"),
                                          ("ByteBuffer", 3, "ByteBuffer.wrap(x.readAllBytes())")]),
        "Map<String, String>": ("map", [("Map<String, String>", 0, "x")]),
        "(String, String)": ("pairs", [("Map<String, String>", 2, "Map.of(k, v)")]),
        "List<String>": ("list", [("List<String>", 0, "x")]),
        "String[]": ("list", [("List<String>", 2, "List.of(x)")]),
        "int": ("number", [("int", 0, "x"), ("long", 0, "x")]),
        "long": ("number", [("long", 0, "x"), ("int", 2, "Math.toIntExact(x)")]),
        "Duration": ("Duration", [("long", 2, "x.getSeconds()"), ("int", 3, "Math.toIntExact(x.getSeconds())")]),
        "KmsClient": ("the type itself", [("KmsClient", 0, "x")]),
        "Region": ("what builds it", [("KmsClient", 3, "KmsClient.builder().region(x).build()")]),
    },
    "python": {
        "bytes": ("bytes", [("bytes", 0, "x"), ("bytearray", 2, "bytearray(x)")]),
        "bytearray": ("bytes", [("bytearray", 0, "x"), ("bytes", 2, "bytes(x)")]),
        "str": ("text", [("str", 0, "x"), ("bytes", 2, "x.encode()"), ("list[str]", 2, "[x]")]),
        "str (base64)": ("base64 text", [("bytes", 2, "base64.b64decode(x)")]),
        "pathlib.Path": ("file / stream", [("IOBase", 2, 'open(x, "rb")'), ("bytes", 2, "x.read_bytes()")]),
        "BinaryIO": ("file / stream", [("IOBase", 0, "x"), ("bytes", 2, "x.read()")]),
        "dict": ("map", [("dict", 0, "x")]),
        "(str, str)": ("pairs", [("dict", 2, "{k: v}")]),
        "list[str]": ("list", [("list[str]", 0, "x")]),
        "tuple[str, ...]": ("list", [("list[str]", 2, "list(x)")]),
        "int": ("number", [("int", 0, "x"), ("positive int", 0, "x")]),
        "timedelta": ("Duration", [("int", 2, "int(x.total_seconds())")]),
        "BaseClient": ("the type itself", [("BaseClient", 0, "x")]),
        "boto3.Session": ("what builds it", [("BaseClient", 2, 'x.client("kms")')]),
    },
    "dotnet": {
        "byte[]": ("bytes", [("MemoryStream", 2, "new MemoryStream(x)")]),
        "MemoryStream": ("bytes", [("MemoryStream", 0, "x")]),
        "string": ("text", [("String", 0, "x"), ("MemoryStream", 3, "new MemoryStream(Encoding.UTF8.GetBytes(x))"),
                            ("List<String>", 2, "new List<string> { x }")]),
        "string (base64)": ("base64 text", [("MemoryStream", 3, "new MemoryStream(Convert.FromBase64String(x))")]),
        "FileInfo": ("file / stream", [("MemoryStream", 3, "new MemoryStream(File.ReadAllBytes(x.FullName))")]),
        "Stream": ("file / stream", [("MemoryStream", 4, (["var copy = new MemoryStream();", "x.CopyTo(copy);"], "copy"))]),
        "Dictionary<string, string>": ("map", [("Dictionary<String, String>", 0, "x")]),
        "(string, string)": ("pairs", [("Dictionary<String, String>", 2, "new Dictionary<string, string> { [k] = v }")]),
        "List<string>": ("list", [("List<String>", 0, "x")]),
        "string[]": ("list", [("List<String>", 2, "x.ToList()")]),
        "int": ("number", [("Int64", 0, "x")]),
        "long": ("number", [("Int64", 0, "x")]),
        "TimeSpan": ("Duration", [("Int64", 2, "(long)x.TotalSeconds")]),
        "AmazonKeyManagementServiceClient": ("the type itself", [("IAmazonKeyManagementService", 0, "x")]),
        "AmazonKeyManagementServiceConfig": ("what builds it",
                                             [("IAmazonKeyManagementService", 2, "new AmazonKeyManagementServiceClient(x)")]),
    },
    "go": {
        "[]byte": ("bytes", [("[]byte", 0, "x")]),
        "string": ("text", [("string", 0, "x"), ("*string", 1, "&x"), ("[]byte", 2, "[]byte(x)"),
                            ("[]string", 2, "[]string{x}")]),
        "string (base64)": ("base64 text", [("[]byte", 4, (["data, err := base64.StdEncoding.DecodeString(x)",
                                                            RETURN_ON_ERROR], "data"))]),
        "string (path)": ("file / stream", [("[]byte", 4, (["data, err := os.ReadFile(x)", RETURN_ON_ERROR], "data"))]),
        "io.Reader": ("file / stream", [("[]byte", 4, (["data, err := io.ReadAll(x)", RETURN_ON_ERROR], "data"))]),
        "map[string]string": ("map", [("map[string]string", 0, "x")]),
        "(string, string)": ("pairs", [("map[string]string", 2, "map[string]string{k: v}")]),
        "[]string": ("list", [("[]string", 0, "x")]),
        "int": ("number", [("int64", 2, "int64(x)"), ("*int64", 3, "aws.Int64(int64(x))")]),
        "int64": ("number", [("int64", 0, "x"), ("*int64", 1, "&x")]),
        "time.Duration": ("Duration", [("int64", 2, "int64(x.Seconds())"),
                                       ("*int64", 3, "aws.Int64(int64(x.Seconds()))")]),
        "*kms.Client": ("the type itself", [("Client", 0, "x")]),
        "aws.Config": ("what builds it", [("Client", 2, "kms.NewFromConfig(x)")]),
    },
    "javascript": {
        "Uint8Array": ("bytes", [("Uint8Array", 0, "x"), ("Buffer", 2, "Buffer.from(x)")]),
        "Buffer": ("bytes", [("Buffer", 0, "x"), ("Uint8Array", 0, "x")]),
        "string": ("text", [("string", 0, "x"), ("Uint8Array", 2, "new TextEncoder().encode(x)"), ("string[]", 2, "[x]")]),
        "string (base64)": ("base64 text", [("Buffer", 2, 'Buffer.from(x, "base64")'),
                                            ("Uint8Array", 2, 'Buffer.from(x, "base64")')]),
        "string (path)": ("file / stream", [("Readable", 2, "fs.createReadStream(x)"), ("Buffer", 2, "fs.readFileSync(x)"),
                                            ("Uint8Array", 2, "fs.readFileSync(x)")]),
        "Readable": ("file / stream", [("Readable", 0, "x"), ("Buffer", 3, "Buffer.concat(await x.toArray())"),
                                       ("Uint8Array", 3, "Buffer.concat(await x.toArray())")]),
        "Record<string, string>": ("map", [("EncryptionContext", 0, "x")]),
        "[string, string]": ("pairs", [("EncryptionContext", 2, "{ [k]: v }")]),
        "string[]": ("list", [("string[]", 0, "x")]),
        "number": ("number", [("number", 0, "x")]),
        "KMSClient": ("the type itself", [("KmsClientSupplier<AwsEsdkKMSInterface>", 2, "() => x")]),
        "KMSClientConfig": ("what builds it", [("KmsClientSupplier<AwsEsdkKMSInterface>", 2, "getClient(KMS, x)")]),
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--shipped", required=True)
    args = parser.parse_args()
    # (api, row, language) -> type the library takes -> call template
    calls = {}
    for path in sorted(Path(args.shipped).glob("*/*.json")):
        artifact = json.loads(path.read_text())
        lang = artifact["language"]
        for api in artifact["apis"]:
            for way in api["ways"]:
                row = way.get("row") or way.get("option")
                for taken in way.get("takes", []):
                    t = short_type(taken["type"])
                    calls.setdefault((api["id"], row, lang), {}).setdefault(t, template(lang, taken["signature"], t))
    others = {}
    for key, (api, row, kinds) in OPTIONS.items():
        for lang, held in HELD.items():
            takes = calls.get((api, row, lang), {})
            rows = []
            for label, (kind, conversions) in held.items():
                if kind not in kinds or not takes:
                    continue
                best = None
                for taken, cost, conversion in conversions:
                    if taken in takes and (best is None or cost < best[0]):
                        best = (cost, taken, conversion)
                if best is None:
                    rows.append([label, None, "", kind])
                    continue
                cost, taken, conversion = best
                setup, value = conversion if isinstance(conversion, tuple) else ([], conversion)
                rows.append([label, cost, "\n".join(setup + [takes[taken].replace("{x}", value)]), kind])
            others.setdefault(key, {})[lang] = sorted(rows, key=lambda r: (r[1] is None, r[1] or 0, r[0]))
    page = json.loads(PAGE.read_text())
    page["others"] = others
    page["others_note"] = ("Java, Python, .NET, Go, JS: calls written from each release's signatures, not compiled. "
                           "api-examples/types/other_languages.py writes them.")
    PAGE.write_text(json.dumps(page, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {sum(len(r) for langs in others.values() for r in langs.values())} rows")


if __name__ == "__main__":
    main()
