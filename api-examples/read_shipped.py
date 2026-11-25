#!/usr/bin/env python3
"""Write surface.json for an ESDK or MPL that already ships in some language.

The types page's rows for Java, Python, .NET, Go and JS show what each released
library takes today. This script downloads one released package, reads its
public API without building anything, and writes surface.json with one id for
each API. build_api_examples.py then puts each parameter on its
Smithy row and says what the customer has for each parameter type.

  java        jars from Maven Central, read with javap. javap -l gives the
              parameter names, from each method's local variable table.
  python      wheels from PyPI, read with ast: __init__ type hints, or the
              :type: lines of a docstring.
  dotnet      NuGet packages, read with reflection by shipped/dotnet.
  go          the module's release tag, read with go/ast by shipped/read_go.go.
  javascript  npm packages, read from their .d.ts files by shipped/read_dts.js.

The Dafny-generated libraries name each input after its Smithy shape
(CreateAwsKmsKeyringInput, with one member per option), so one function,
smithy_apis, reads all of them. The hand-written libraries (the Java and
Python ESDK, and every JavaScript package) name things their own way, and the
*_HAND tables below map their classes and parameters to API ids and options.

Each setter way has takes: one {type, signature} per type that the option
accepts, where signature is the code that passes it.

Usage:
  read_shipped.py --language java --library esdk --work <empty dir> --out surface.json
"""

import argparse
import ast
import io
import json
import re
import shutil
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from build_api_examples import option_key, short_type

HERE = Path(__file__).resolve().parent
NAMES = HERE / "smithy-names.json"

PACKAGES = {
    ("java", "mpl"): {"maven": "software.amazon.cryptography:aws-cryptographic-material-providers"},
    ("java", "esdk"): {"maven": "com.amazonaws:aws-encryption-sdk-java", "major": 3},
    ("python", "mpl"): {"pypi": "aws-cryptographic-material-providers"},
    ("python", "esdk"): {"pypi": "aws-encryption-sdk"},
    ("dotnet", "mpl"): {"nuget": "AWS.Cryptography.MaterialProviders"},
    ("dotnet", "esdk"): {"nuget": "AWS.Cryptography.EncryptionSDK"},
    ("go", "mpl"): {"git": "https://github.com/aws/aws-cryptographic-material-providers-library", "module": "releases/go/mpl"},
    ("go", "esdk"): {"git": "https://github.com/aws/aws-encryption-sdk", "module": "releases/go/encryption-sdk"},
    ("javascript", "mpl"): {"npm": "@aws-crypto/client-node"},
    ("javascript", "esdk"): {"npm": "@aws-crypto/client-node"},
}

# The Java MPL's package, and each library's client class in each Dafny-generated language.
JAVA_MPL = "software.amazon.cryptography.materialproviders"
CLIENTS = {
    ("java", "mpl"): "MaterialProviders",
    ("python", "mpl"): "AwsCryptographicMaterialProviders",
    ("dotnet", "mpl"): "MaterialProviders",
    ("dotnet", "esdk"): "ESDK",
}

# The Java ESDK 3.x: AwsCrypto's builder sets up the client, and its
# methods take the encrypt and decrypt inputs as parameters.
JAVA_ESDK = "com.amazonaws.encryptionsdk.AwsCrypto"
JAVA_ESDK_HAND = {
    "encrypt": {"methods": ["encryptData", "encryptString", "createEncryptingStream"],
                "rename": {"is": "plaintext", "os": "outputStream", "provider": "masterKeyProvider"}},
    # decryptString names its CryptoMaterialsManager parameter provider.
    "decrypt": {"methods": ["decryptData", "decryptString", "createDecryptingStream", "createUnsignedMessageDecryptingStream"],
                "rename": {"is": "ciphertext", "os": "outputStream",
                           "provider": {"MasterKeyProvider<K>": "masterKeyProvider", "CryptoMaterialsManager": "materialsManager"}}},
}

# The Python ESDK: EncryptionSDKClient(**kwargs) and client.encrypt(**kwargs)
# document each keyword argument with :param: and :type: lines.
PYTHON_ESDK_HAND = {
    "client": {"class": "EncryptionSDKClientConfig", "call": "EncryptionSDKClient", "rename": {}},
    "encrypt": {"method": "encrypt", "rename": {"source": "plaintext", "algorithm": "algorithmSuiteId"}},
    "decrypt": {"method": "decrypt", "rename": {"source": "ciphertext"}},
}

# JavaScript: one export per API, and the names of its options that differ
# from Smithy's.
JS_HAND = {
    "mpl": {
        "aws-kms-keyring": {"export": "KmsKeyringNode", "rename": {"generatorKeyId": "kmsKeyId", "clientProvider": "kmsClient"}},
        "aws-kms-multi-keyring": {"export": "KmsKeyringNode",
                                  "rename": {"generatorKeyId": "generator", "keyIds": "kmsKeyIds", "clientProvider": "clientSupplier"}},
        "aws-kms-mrk-keyring": {"export": "AwsKmsMrkAwareSymmetricKeyringNode", "rename": {"keyId": "kmsKeyId", "client": "kmsClient"}},
        "aws-kms-mrk-discovery-keyring": {"export": "AwsKmsMrkAwareSymmetricDiscoveryKeyringNode", "rename": {"client": "kmsClient"}},
        "aws-kms-mrk-multi-keyring": {"export": "buildAwsKmsMrkAwareStrictMultiKeyringNode",
                                      "rename": {"generatorKeyId": "generator", "keyIds": "kmsKeyIds", "clientProvider": "clientSupplier"}},
        "aws-kms-mrk-discovery-multi-keyring": {"export": "buildAwsKmsMrkAwareDiscoveryMultiKeyringNode",
                                                "rename": {"clientProvider": "clientSupplier"}},
        "hierarchical-keyring": {"export": "KmsHierarchicalKeyRingNode", "rename": {"cacheLimitTtl": "ttlSeconds"}},
        "raw-aes-keyring": {"export": "RawAesKeyringNode", "rename": {"unencryptedMasterKey": "wrappingKey", "wrappingSuite": "wrappingAlg"}},
        "raw-rsa-keyring": {"export": "RawRsaKeyringNode", "rename": {"padding": "paddingScheme"}},
        "multi-keyring": {"export": "MultiKeyringNode", "rename": {"children": "childKeyrings"}},
        "default-cmm": {"export": "NodeDefaultCryptographicMaterialsManager", "rename": {}},
    },
    "esdk": {
        "client": {"export": "buildClient", "rename": {"options": {"CommitmentPolicy": "commitmentPolicy"}}},
        "encrypt": {"export": "buildClient().encrypt", "method": "encrypt",
                    "rename": {"cmm": {"KeyringNode": "keyring", "NodeMaterialsManager": "materialsManager"},
                               "suiteId": "algorithmSuiteId"}},
        "decrypt": {"export": "buildClient().decrypt", "method": "decrypt",
                    "rename": {"cmm": {"KeyringNode": "keyring", "NodeMaterialsManager": "materialsManager"}}},
    },
}

UPPER = {"aws", "kms", "mrk", "ecdh", "rsa", "aes", "cmm"}


def renamed(table, name, type_text):
    """A parameter's option name from a rename table. A rename can depend on the
    type, for a parameter such as JavaScript's cmm that takes a keyring or a CMM."""
    r = table.get(name, name)
    return r.get(short_type(type_text), name) if isinstance(r, dict) else r


def in_scope(api_id):
    """The APIs that the live surfaces cover: keyrings, CMMs, and the ESDK client, encrypt and decrypt."""
    return api_id.endswith(("-keyring", "-cmm")) or api_id in ("client", "encrypt", "decrypt")


def api_of(api_id, type_name, ways):
    group = "Keyrings" if api_id.endswith("-keyring") else "CMMs" if api_id.endswith("-cmm") else "Client"
    words = [w.upper() if w in UPPER else w for w in api_id.split("-")]
    name = " ".join(words)
    return {"id": api_id, "group": group, "name": name[0].upper() + name[1:], "type": type_name, "ways": ways}


def setter(name, takes):
    """A setter way, from [(type, signature)]. Types it takes twice are listed once."""
    seen = {}
    for t, sig in takes:
        seen.setdefault(t, sig)
    return {"id": name, "option": name, "kind": "setter", "signature": next(iter(seen.values())),
            "takes": [{"type": t, "signature": s} for t, s in seen.items()]}


def merge_setters(ways):
    """Ways with one id, such as a parameter of several overloads, become one way with all their takes."""
    out = {}
    for w in ways:
        if w["kind"] == "setter" and w["id"] in out:
            have = {t["type"] for t in out[w["id"]]["takes"]}
            out[w["id"]]["takes"] += [t for t in w["takes"] if t["type"] not in have]
        elif w["id"] in out:
            out[w["id"]]["signature"] += "\n" + w["signature"]
        else:
            out[w["id"]] = w
    return list(out.values())


def split_top(text, sep=","):
    """Split at sep where it is not inside <>, [] or ()."""
    parts, depth, cur = [], 0, ""
    for ch in text:
        if ch in "<[(":
            depth += 1
        elif ch in ">])":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    return parts + [cur.strip()] if cur.strip() else parts


# ---------- versions and downloads ----------

def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def newest(versions, major=None):
    """The newest release version: no pre-release suffix, and in the given major version if any."""
    plain = [v for v in versions if re.fullmatch(r"\d+(\.\d+)*", v)]
    if major is not None:
        plain = [v for v in plain if v.split(".")[0] == str(major)]
    return max(plain, key=lambda v: tuple(int(x) for x in v.split(".")))


def download(pkg, work):
    """Download one released package into work. Returns (package name, version, path)."""
    if "maven" in pkg:
        group, artifact = pkg["maven"].split(":")
        base = f"https://repo1.maven.org/maven2/{group.replace('.', '/')}/{artifact}"
        meta = ET.fromstring(fetch(f"{base}/maven-metadata.xml"))
        version = newest([v.text for v in meta.iter("version")], pkg.get("major"))
        jar = work / f"{artifact}-{version}.jar"
        jar.write_bytes(fetch(f"{base}/{version}/{artifact}-{version}.jar"))
        return pkg["maven"], version, jar
    if "pypi" in pkg:
        info = json.loads(fetch(f"https://pypi.org/pypi/{pkg['pypi']}/json"))
        version = info["info"]["version"]
        wheel = next(u for u in info["releases"][version] if u["packagetype"] == "bdist_wheel")
        out = work / "wheel"
        zipfile.ZipFile(io.BytesIO(fetch(wheel["url"]))).extractall(out)
        return pkg["pypi"], version, out
    if "nuget" in pkg:
        index = json.loads(fetch(f"https://api.nuget.org/v3-flatcontainer/{pkg['nuget'].lower()}/index.json"))
        return pkg["nuget"], newest(index["versions"]), None
    if "npm" in pkg:
        version = json.loads(fetch(f"https://registry.npmjs.org/{pkg['npm']}/latest"))["version"]
        out = work / "js"
        out.mkdir()
        (out / "package.json").write_text('{"private": true}\n')
        subprocess.run(["npm", "install", "--no-audit", "--no-fund", "--loglevel=error",
                        f"{pkg['npm']}@{version}", "typescript@5"], cwd=out, check=True)
        return pkg["npm"], version, out
    # A Go module's versions are its repository's tags <module>/v<version>.
    refs = subprocess.run(["git", "ls-remote", "--tags", pkg["git"], f"refs/tags/{pkg['module']}/v*"],
                          capture_output=True, text=True, check=True).stdout
    prefix = f"refs/tags/{pkg['module']}/v"
    version = newest([line.split(prefix)[1] for line in refs.splitlines() if prefix in line])
    out = work / "go"
    subprocess.run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse",
                    "-c", "advice.detachedHead=false",
                    "--branch", f"{pkg['module']}/v{version}", pkg["git"], str(out)], check=True)
    subprocess.run(["git", "-C", str(out), "sparse-checkout", "set", pkg["module"]], check=True)
    name = pkg["git"].removeprefix("https://") + "/" + pkg["module"]
    return name, version, out / pkg["module"]


# ---------- Dafny-generated libraries ----------

def smithy_apis(names, members, operation, client, type_name):
    """The APIs of a Dafny-generated library.

    members(shape) gives [(member, [(type, signature)])], or None when the
    language has no such shape. operation(op) gives (way id, signature) for a
    client operation, or None. client() gives (way id, signature) for the
    client's constructor, or None.
    """
    apis = []
    for api_id, entry in names.items():
        if not in_scope(api_id):
            continue
        shape = entry["shape"].split("#")[1]
        found = members(shape)
        if found is None:
            continue
        ways = []
        if api_id == "client" and client():
            way_id, sig = client()
            ways.append({"id": way_id, "option": None, "kind": "constructor", "signature": sig})
        # A keyring or CMM is built by the client operation Create<Type>, whose input is Create<Type>Input.
        made_by = [shape.removesuffix("Input")] if not entry["operations"] and shape.startswith("Create") else []
        for op in entry["operations"] + made_by:
            found_op = operation(op)
            if found_op:
                way_id, sig = found_op
                kind = "method" if op in entry["operations"] else "constructor"
                ways.append({"id": way_id, "option": op if kind == "method" else None, "kind": kind, "signature": sig})
        ways += [setter(m, takes) for m, takes in found]
        apis.append(api_of(api_id, type_name(shape), ways))
    return apis


# ---------- Java ----------

JAVAP_CLASS = re.compile(r"^(?:public )?(?:(?:abstract|final) )*(?:class|interface) ([\w.$]+)")
JAVAP_METHOD = re.compile(r"^  public (?P<mods>(?:(?:static|abstract|final|synchronized|default|native) )*)"
                          r"(?:<.*?> )?(?P<ret>.+) (?P<name>[\w$]+)\((?P<params>.*)\)(?: throws .*)?;$")
JAVAP_ANY_METHOD = re.compile(r"^  \S.*\(.*\).*;$")
JAVAP_LOCAL = re.compile(r"^\s+0\s+\d+\s+(\d+)\s+(\S+)\s+\S+$")


def parse_javap(text):
    """javap -l output: {class: [{name, returns, static, params: [{type, name}]}]}.

    A parameter's name is None when the method has no local variable table,
    as an interface method does.
    """
    classes, methods, method, locals_ = {}, None, None, []

    def finish():
        if method is None:
            return
        names = [n for _, n in sorted(locals_, key=lambda x: int(x[0])) if n != "this"]
        for i, p in enumerate(method["params"]):
            p["name"] = names[i] if i < len(names) else None

    for line in text.splitlines():
        m = JAVAP_CLASS.match(line)
        if m:
            finish()
            method, locals_ = None, []
            methods = classes.setdefault(m.group(1), [])
            continue
        if JAVAP_ANY_METHOD.match(line) and methods is not None:
            finish()
            method, locals_ = None, []
            m = JAVAP_METHOD.match(line)
            if m:
                method = {"name": m["name"], "returns": m["ret"], "static": "static" in m["mods"],
                          "params": [{"type": t, "name": None} for t in split_top(m["params"])]}
                methods.append(method)
            continue
        m = JAVAP_LOCAL.match(line)
        if m and method is not None:
            locals_.append(m.groups())
    finish()
    return classes


def javap(jar, classes):
    # javap prints what it finds and an error for each class it does not, so its exit code is ignored.
    out = subprocess.run(["javap", "-l", "-cp", str(jar), *classes], capture_output=True, text=True).stdout
    return parse_javap(out)


def java_call(m):
    params = ", ".join(" ".join(x for x in (short_type(p["type"]), p["name"]) if x) for p in m["params"])
    return f"{m['name']}({params})"


def java_mpl(jar, names):
    in_scope_shapes = [e["shape"].split("#")[1] for i, e in names.items() if in_scope(i)]
    client = f"{JAVA_MPL}.{CLIENTS[('java', 'mpl')]}"
    found = javap(jar, [client] + [f"{JAVA_MPL}.model.{s}$Builder" for s in in_scope_shapes])

    def members(shape):
        builder = found.get(f"{JAVA_MPL}.model.{shape}$Builder")
        if builder is None:
            return None
        return [(m["name"], [(m["params"][0]["type"], f"{shape}.builder().{m['name']}({short_type(m['params'][0]['type'])})")])
                for m in builder if len(m["params"]) == 1]

    def operation(op):
        m = next((m for m in found.get(client, []) if m["name"] == op), None)
        return (op, f"materialProviders.{op}({short_type(m['params'][0]['type'])})") if m else None

    return smithy_apis(names, members, operation, lambda: ("builder", f"{CLIENTS[('java', 'mpl')]}.builder()"),
                       lambda s: f"{JAVA_MPL}.model.{s}")


def java_esdk(jar):
    found = javap(jar, [JAVA_ESDK, f"{JAVA_ESDK}$Builder"])
    builder = [m for m in found[f"{JAVA_ESDK}$Builder"] if m["name"].startswith("with")]
    statics = [m for m in found[JAVA_ESDK] if m["static"] and m["name"] in ("builder", "standard")]
    client = [{"id": m["name"], "option": None, "kind": "constructor", "signature": f"AwsCrypto.{m['name']}()"} for m in statics]
    for m in builder:
        option = m["name"][4].lower() + m["name"][5:]
        client.append(setter(option, [(m["params"][0]["type"], f"AwsCrypto.builder().{java_call(m)}")]))
    apis = [api_of("client", JAVA_ESDK, client)]
    for api_id, hand in JAVA_ESDK_HAND.items():
        ways = []
        for m in found[JAVA_ESDK]:
            if m["name"] not in hand["methods"]:
                continue
            call = f"crypto.{java_call(m)}"
            ways.append({"id": m["name"], "option": api_id, "kind": "method", "signature": call})
            for p in m["params"]:
                ways.append(setter(renamed(hand["rename"], p["name"], p["type"]), [(p["type"], call)]))
        apis.append(api_of(api_id, JAVA_ESDK, merge_setters(ways)))
    return apis


# ---------- Python ----------

def py_types(annotation):
    """The types that a type hint allows, with Optional and Union opened up and None dropped."""
    text = annotation.strip().strip("'\"")
    m = re.fullmatch(r"(?:typing\.)?(Optional|Union)\[(.*)\]", text)
    parts = split_top(m.group(2)) if m else split_top(text, "|")
    if len(parts) > 1 or m:
        return [t for part in parts for t in py_types(part) if t != "None"]
    return [text]


def doc_types(doc):
    """{parameter: [types]} from a docstring's :param [type] name: and :type name: lines."""
    out = {}
    for line in (doc or "").splitlines():
        m = re.match(r"\s*:param (?:(\S+) )?(\w+):", line)
        if m:
            out.setdefault(m.group(2), [m.group(1)] if m.group(1) else [])
        m = re.match(r"\s*:type (\w+): (.+)$", line)
        if m:
            out[m.group(1)] = [t for t in re.split(r",\s*(?:or\s+)?|\s+or\s+", m.group(2).strip()) if t and t != "None"]
    return out


def py_classes(path):
    return {n.name: n for n in ast.parse(path.read_text()).body if isinstance(n, ast.ClassDef)}


def py_method(cls, name):
    return next((n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name), None)


def python_mpl(wheel, names):
    gen = wheel / "aws_cryptographic_material_providers/smithygenerated/aws_cryptography_materialproviders"
    models = {**py_classes(gen / "models.py"), **py_classes(gen / "config.py")}
    client = py_classes(gen / "client.py")[CLIENTS[("python", "mpl")]]

    def members(shape):
        init = py_method(models[shape], "__init__") if shape in models else None
        if init is None:
            return None
        args = init.args.kwonlyargs + init.args.args[1:]
        return [(a.arg, [(t, f"{shape}({a.arg}={short_type(t)})") for t in py_types(ast.unparse(a.annotation))])
                for a in args if a.annotation is not None]

    def operation(op):
        m = next((n for n in client.body if isinstance(n, ast.FunctionDef) and option_key(n.name) == option_key(op)), None)
        return (m.name, f"material_providers.{m.name}(input)") if m else None

    def make_client():
        init = py_method(client, "__init__")
        params = ", ".join(f"{a.arg}: {short_type(ast.unparse(a.annotation))}" for a in init.args.args[1:] if a.annotation)
        return "new", f"{client.name}({params})"

    return smithy_apis(names, members, operation, make_client, lambda s: f"{gen.relative_to(wheel).as_posix().replace('/', '.')}.models.{s}")


def python_esdk(wheel):
    classes = py_classes(wheel / "aws_encryption_sdk/__init__.py")
    apis = []
    for api_id, hand in PYTHON_ESDK_HAND.items():
        if "class" in hand:
            doc, call = ast.get_docstring(classes[hand["class"]]), hand["call"]
            ways = [{"id": call, "option": None, "kind": "constructor", "signature": f"{call}(**kwargs)"}]
        else:
            doc, call = ast.get_docstring(py_method(classes["EncryptionSDKClient"], hand["method"])), f"client.{hand['method']}"
            ways = [{"id": hand["method"], "option": api_id, "kind": "method", "signature": f"{call}(**kwargs)"}]
        for name, types in doc_types(doc).items():
            if name == "config":
                continue
            ways.append(setter(hand["rename"].get(name, name), [(t, f"{call}({name}={short_type(t)})") for t in types]))
        apis.append(api_of(api_id, "aws_encryption_sdk.EncryptionSDKClient", ways))
    return apis


# ---------- .NET ----------

def dotnet(package, version, work):
    project = work / "dotnet"
    shutil.copytree(HERE / "shipped/dotnet", project)
    out = subprocess.run(["dotnet", "run", f"-p:ShippedPackage={package}", f"-p:ShippedVersion={version}", "--", package],
                         cwd=project, capture_output=True, text=True)
    if out.returncode:
        sys.exit(out.stdout + out.stderr)
    return json.loads(out.stdout)["types"]


def dotnet_apis(types, names, client_class, namespace):
    def members(shape):
        if shape not in types:
            return None
        return [(p["name"], [(p["type"], f"new {shape} {{ {p['name']} = {p['type']} }}")]) for p in types[shape]["properties"]]

    def operation(op):
        m = next((m for m in types[client_class]["methods"] if m["name"] == op), None)
        return (op, f"{client_class[0].lower()}{client_class[1:]}.{op}({m['parameters'][0]['type']})") if m else None

    def client():
        c = next((c for c in types[client_class]["constructors"] if c["parameters"] and c["parameters"][0]["type"].endswith("Config")), None)
        return ("new", f"new {client_class}({c['parameters'][0]['type']})") if c else None

    return smithy_apis(names, members, operation, client, lambda s: f"{namespace}.{s}")


# ---------- Go ----------

def go_apis(module_dir, names):
    out = subprocess.run(["go", "run", str(HERE / "shipped/read_go.go"), str(module_dir)],
                         capture_output=True, text=True)
    if out.returncode:
        sys.exit(out.stderr)
    found = json.loads(out.stdout)
    config = names["client"]["shape"].split("#")[1]
    types_pkg = next(k.split(".")[0] for k in found["structs"] if k.endswith(f"smithygeneratedtypes.{config}"))
    client_pkg = types_pkg.removesuffix("types")

    def members(shape):
        fields = found["structs"].get(f"{types_pkg}.{shape}")
        if fields is None:
            return None
        return [(f["name"], [(f["type"], f"{shape}{{{f['name']}: {short_type(f['type'])}}}")]) for f in fields]

    def operation(op):
        fn = next((f for f in found["functions"] if f["receiver"] == f"{client_pkg}.Client" and f["name"] == op), None)
        return (op, f"client.{op}(ctx, {short_type(fn['params'][-1]['type'])})") if fn else None

    def client():
        fn = next((f for f in found["functions"] if f["package"] == client_pkg and f["name"] == "NewClient"), None)
        return ("NewClient", f"{client_pkg}.NewClient({short_type(fn['params'][0]['type'])})") if fn else None

    return smithy_apis(names, members, operation, client, lambda s: f"{types_pkg}.{s}")


# ---------- JavaScript ----------

def js_apis(js_dir, package, library):
    hand = JS_HAND[library]
    exports = sorted({h["export"] for h in hand.values()})
    out = subprocess.run(["node", str(HERE / "shipped/read_dts.js"), str(js_dir), package, *exports],
                         capture_output=True, text=True)
    if out.returncode:
        sys.exit(out.stderr)
    found = json.loads(out.stdout)
    apis = []
    for api_id, h in hand.items():
        name = h["export"]
        if name not in found:
            continue
        callee = f"client.{h['method']}" if "method" in h else name
        kind = "method" if "method" in h else "constructor"
        new = "new " if name[0].isupper() and not name.startswith("build") else ""
        # TypeScript names a destructured parameter __0.
        def shown(p):
            return "{ ... }" if p["name"].startswith("__") else p["name"]

        ways = [{"id": h.get("method", name), "option": api_id if kind == "method" else None, "kind": kind,
                 "signature": "\n".join(f"{new}{callee}({', '.join(shown(p) for p in s['params'])})" for s in found[name])}]

        def option(param, t):
            return renamed(h["rename"], param, t)

        for sig in found[name]:
            for p in sig["params"]:
                objects = {o["type"]: o for o in p.get("props", [])}
                by_type = h["rename"].get(p["name"])
                for t in p["union"]:
                    # An options object gives one option per property. A type that the rename
                    # table names, such as NodeMaterialsManager for cmm, is a value of its own.
                    if t in objects and not (isinstance(by_type, dict) and t in by_type):
                        for q in objects[t]["props"]:
                            ways += [setter(option(q["name"], u), [(u, f"{new}{callee}({{ {q['name']}: {u} }})")]) for u in q["union"]]
                    else:
                        ways.append(setter(option(p["name"], t), [(t, f"{new}{callee}({p['name']}: {t})")]))
        apis.append(api_of(api_id, name, merge_setters(ways)))
    return apis


def read(language, library, work):
    pkg = PACKAGES[(language, library)]
    names = json.loads(NAMES.read_text())["libraries"][library]
    package, version, path = download(pkg, work)
    if language == "java":
        apis = java_mpl(path, names) if library == "mpl" else java_esdk(path)
    elif language == "python":
        apis = python_mpl(path, names) if library == "mpl" else python_esdk(path)
    elif language == "dotnet":
        apis = dotnet_apis(dotnet(package, version, work), names, CLIENTS[("dotnet", library)], package)
    elif language == "go":
        apis = go_apis(path, names)
    else:
        apis = js_apis(path, package, library)
    return {"schema": 1, "language": language, "library": library,
            "shipped": {"package": package, "version": version}, "apis": apis}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--language", required=True, choices=sorted({k[0] for k in PACKAGES}))
    p.add_argument("--library", required=True, choices=["mpl", "esdk"])
    p.add_argument("--work", required=True, type=Path, help="an empty directory for the downloads")
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args(argv)
    args.work.mkdir(parents=True, exist_ok=True)
    surface = read(args.language, args.library, args.work.resolve())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(surface, indent=2) + "\n")
    ways = sum(len(a["ways"]) for a in surface["apis"])
    print(f"{surface['shipped']['package']} {surface['shipped']['version']}: {len(surface['apis'])} apis, {ways} ways")


if __name__ == "__main__":
    sys.exit(main())
