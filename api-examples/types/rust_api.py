#!/usr/bin/env python3
"""List every Rust API that the types page shows, with every option of each, and write rust-api.json.

  rust_api.py --rust-repo <aws-crypto-tools-rust checkout>

It runs rustdoc on the mpl and esdk crates with the nightly toolchain, and reads the result with the Rust
repo's scripts/smithy-conformance/rust_surface.py. The APIs are:
  - each built-in component: a type that converts into a shared handle, like RawAesKeyring into
    SharedKeyring. Its options are the setters of the builder that its builder() returns, or else the
    parameters of its constructors.
  - the ESDK client, and its encrypt and decrypt calls. Their options are the setters of their builders.

compile_rust_types.py reads rust-api.json. So a new keyring or setter shows on the page after these two
scripts run again.
"""
import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "rust-api.json"
CACHE = Path(os.environ.get("RUST_TYPES_CACHE", Path.home() / ".cache" / "crypto-tools-api-examples"))
REPO_URL = "https://github.com/aws/aws-crypto-tools-rust"
CRATES = ["mpl", "esdk"]
# Each handle and the group its built-in components show under, in page order.
HANDLES = [("SharedKeyring", "Keyrings"), ("SharedCmm", "CMMs"), ("SharedKeyStore", "Key stores"),
           ("SharedCmc", "Caches"), ("SharedBranchKeyIdSupplier", "Branch key ID suppliers")]
OPERATIONS = ["encrypt", "decrypt"]
ACRONYMS = {"aws": "AWS", "aes": "AES", "kms": "KMS", "cmm": "CMM", "cmc": "CMC", "rsa": "RSA", "ecdh": "ECDH",
            "mrk": "MRK", "id": "ID"}
PRELUDE = {"String", "Vec", "Option", "Box", "Result"}


def load_rust_surface(rust_repo):
    path = Path(rust_repo) / "scripts" / "smithy-conformance" / "rust_surface.py"
    spec = importlib.util.spec_from_file_location("rust_surface", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rustdoc(rust_repo, crate):
    """The crate's rustdoc JSON. rust_surface.py's main runs the same commands."""
    crate_dir = Path(rust_repo) / crate
    env = {**os.environ, "CARGO_TARGET_DIR": str(CACHE / "rustdoc-target")}
    subprocess.run(["cargo", "+nightly", "rustdoc", "-q", "--lib", "--", "-Z", "unstable-options",
                    "--output-format", "json"], cwd=crate_dir, env=env, check=True, stderr=subprocess.DEVNULL)
    meta = json.loads(subprocess.run(["cargo", "metadata", "--no-deps", "--format-version", "1"], cwd=crate_dir,
                                     env=env, check=True, capture_output=True).stdout)
    manifest = os.path.realpath(crate_dir / "Cargo.toml")
    pkg = next(p for p in meta["packages"] if os.path.realpath(p["manifest_path"]) == manifest)
    lib = next(t for t in pkg["targets"] if {"lib", "rlib", "staticlib", "cdylib"} & set(t["kind"]))
    return json.loads((CACHE / "rustdoc-target" / "doc" / (lib["name"].replace("-", "_") + ".json")).read_text())


def path_renderer(rs, doc, local, ours):
    """rust_surface.render, except each type is named by a path that code can use.

    local maps a rustdoc id in this crate to its public path. ours maps a name in a crate read before, like
    aws_crypto_mpl's EsdkCommitmentPolicy when reading aws_esdk, to its public path there, because rustdoc
    gives the module it is defined in, which may be private. A standard library type gets its std path, or
    its bare name when it is in the prelude. An AWS SDK type in a module named after it, like
    aws_sdk_kms::client::Client, gets the crate's own re-export, aws_sdk_kms::Client.
    """
    our_crates = {p.split("::")[0] for p in ours.values()}

    def name_of(v):
        iid = str(v.get("id"))
        name = rs.REAL_NAMES.get(iid, v["path"].split("::")[-1])
        if iid in local:
            return local[iid]
        found = doc["paths"].get(iid)
        if not found or found.get("crate_id", 0) == 0:
            return name
        parts = found["path"]
        if parts[0] in ("std", "core", "alloc"):
            return name if name in PRELUDE else "std::" + "::".join(parts[1:])
        if parts[0] in our_crates:
            return ours.get(name, "::".join(parts))
        if len(parts) == 3 and parts[1] == parts[2].lower():
            return f"{parts[0]}::{parts[2]}"
        return "::".join(parts)

    def render(t):
        if t is None:
            return "()"
        (k, v), = t.items()
        if k in ("primitive", "generic"):
            return v
        if k == "resolved_path":
            name = name_of(v)
            args = v.get("args") or {}
            if "angle_bracketed" in args:
                parts = [render(a["type"]) if "type" in a else str(a["const"].get("expr"))
                         for a in args["angle_bracketed"]["args"] if "type" in a or "const" in a]
                for c in args["angle_bracketed"].get("constraints", []):
                    b = c.get("binding", {})
                    if "equality" in b and "type" in b["equality"]:
                        parts.append(f"{c['name']}={render(b['equality']['type'])}")
                if parts:
                    name += "<" + ", ".join(parts) + ">"
            return name
        if k == "borrowed_ref":
            return "&" + ("mut " if v["is_mutable"] else "") + render(v["type"])
        if k == "slice":
            return "[" + render(v) + "]"
        if k == "array":
            return f"[{render(v['type'])}; {v['len']}]"
        if k == "tuple":
            return "(" + ", ".join(render(x) for x in v) + ")"
        if k == "impl_trait":
            return "impl " + " + ".join(rs.bound(b) for b in v)
        if k == "dyn_trait":
            return "dyn " + " + ".join(render({"resolved_path": p["trait"]}) for p in v["traits"])
        return rs.render(t)

    return render


def surfaces(rs, doc, ours):
    """The crate's surface twice: with bare type names, for the page, and with paths, for code.

    ours maps each public name in the crates read before to its path. This crate's names are added to it.
    """
    short = rs.walk(doc)
    by_name = {}
    for path, t in list(short["types"].items()) + list(short["traits"].items()):
        by_name.setdefault(t["name"], path)
    local = {iid: by_name[item["name"]] for iid, item in doc["index"].items()
             if item.get("crate_id") == 0 and item.get("name") in by_name}
    original = rs.render
    rs.render = path_renderer(rs, doc, local, ours)
    try:
        full = rs.walk(doc)
    finally:
        rs.render = original
    for name, path in by_name.items():
        ours.setdefault(name, path)
    return short, full


def display_name(type_name):
    words = re.findall(r"[A-Z][a-z0-9]*", type_name.replace("DynamoDb", "Dynamodb"))
    return " ".join(ACRONYMS.get(w.lower(), w if i == 0 else w.lower()) for i, w in enumerate(words)).replace(
        "Dynamodb", "DynamoDB")


def api_id(type_name):
    return "-".join(w.lower() for w in re.findall(r"[A-Z][a-z0-9]*", type_name))


def is_setter(m):
    return (m["receiver"] in ("self", "&mut self") and m["output"] in ("Self", "&mut Self")
            and m["name"] not in ("build", "send"))


def first_line(doc):
    return next((line.strip() for line in (doc or "").splitlines() if line.strip()), "")


def options_of(short_methods, full_methods):
    """Each option of a builder: its setter, its set_ setter, and what they take, with and without paths."""
    full = {m["name"]: m for m in full_methods}
    found = {}
    for m in short_methods:
        if not is_setter(m):
            continue
        name = m["name"][len("set_"):] if m["name"].startswith("set_") else m["name"]
        opt = found.setdefault(name, {"name": name, "setter": None, "set": None, "ctor": None})
        takes = ", ".join(t for _, t in m["inputs"])
        code = ", ".join(t for _, t in full[m["name"]]["inputs"])
        if m["name"].startswith("set_"):
            opt.update(set=m["name"], set_takes=takes, set_takes_code=code)
        else:
            opt.update(setter=m["name"], takes=takes, takes_code=code, params=len(m["inputs"]),
                       doc=first_line(m["docs"]))
    for opt in found.values():
        # An option with only a set_ setter takes what that setter's Option holds.
        if opt["setter"] is None:
            inner = lambda t: t[len("Option<"):-1] if t.startswith("Option<") else t  # noqa: E731
            opt.update(takes=inner(opt["set_takes"]), takes_code=inner(opt["set_takes_code"]), params=1, doc="")
    return list(found.values())


def ctor_options(short_methods, full_methods):
    """The parameters of each constructor that takes one value, like DefaultCmm::new(keyring)."""
    full = {m["name"]: m for m in full_methods}
    out = []
    for m in short_methods:
        if m["receiver"] is None and len(m["inputs"]) == 1 and m["output"] in ("Self",):
            (param, takes), = m["inputs"]
            out.append({"name": param, "setter": None, "set": None, "ctor": m["name"], "takes": takes,
                        "takes_code": full[m["name"]]["inputs"][0][1], "params": 1, "doc": first_line(m["docs"])})
    return out


def builder_path(t):
    """The path of the builder that t's builder() returns, or None."""
    m = next((m for m in t["methods"] if m["name"] == "builder" and m["receiver"] is None), None)
    return m["output_path"] if m else None


def type_named(types, name):
    found = [p for p, t in types.items() if t["name"] == name]
    return found[0] if len(found) == 1 else None


def component_apis(lib, short, full, handles):
    apis = []
    for handle, group in HANDLES:
        path = type_named(short["types"], handle)
        if path is None:
            continue
        members = sorted(tr[len("FromUnshared<"):-1] for tr in short["types"][path]["traits"]
                         if tr.startswith("FromUnshared<") and tr[len("FromUnshared<"):-1] not in (handle, "T"))
        member_paths = [type_named(short["types"], m) for m in members]
        handles[handle] = {"path": path, "group": group, "members": [p for p in member_paths if p]}
        for name, member in zip(members, member_paths):
            if member is None:
                continue
            t, f = short["types"][member], full["types"][member]
            builder = builder_path(t)
            if builder in short["types"]:
                options = options_of(short["types"][builder]["methods"], full["types"][builder]["methods"])
                start, strip, shown = f"{member}::builder()", f"{member}::builder()", f"{name}::builder()"
            else:
                options = ctor_options(t["methods"], f["methods"])
                start, strip, shown = member, member, name
            apis.append({"lib": lib, "id": api_id(name), "type": name, "group": group, "name": display_name(name),
                         "path": member, "start": start, "strip": strip, "shown": shown, "options": options})
    return apis


def esdk_apis(short, full):
    types, full_types = short["types"], full["types"]
    clients = [p for p, t in types.items()
               if all(any(m["name"] == op and m["receiver"] == "&self" for m in t["methods"]) for op in OPERATIONS)]
    if len(clients) != 1:
        sys.exit(f"expected one type with {OPERATIONS} methods, found {clients}")
    path = clients[0]
    client = types[path]
    builder_path = next(m["output_path"] for m in client["methods"] if m["name"] == "builder")
    apis = [{"lib": "esdk", "id": "client", "type": client["name"], "group": "Client", "name": client["name"],
             "path": path, "start": f"{path}::builder()", "strip": f"{path}::builder()",
             "shown": f"{client['name']}::builder()",
             "options": options_of(types[builder_path]["methods"], full_types[builder_path]["methods"])}]
    for op in OPERATIONS:
        fluent = next(m["output_path"] for m in client["methods"] if m["name"] == op)
        apis.append({"lib": "esdk", "id": op, "type": op, "group": "Client", "name": op.capitalize(),
                     "path": fluent, "start": f"client.{op}()", "strip": "client", "shown": "client",
                     "options": options_of(types[fluent]["methods"], full_types[fluent]["methods"])})
    return apis


def docs_of(crate, doc, short, commit):
    """Each public type's and trait's doc, and a link to where it is defined, for the page's side pane."""
    out = {}
    spans = {item["name"]: item.get("span") for item in doc["index"].values()
             if item.get("crate_id") == 0 and item.get("span") and item.get("name")}
    for path, t in list(short["types"].items()) + list(short["traits"].items()):
        span = spans.get(t["name"])
        url = None
        if span:
            file = span["filename"]
            file = file if file.startswith(crate + "/") else f"{crate}/{file}"
            url = f"{REPO_URL}/blob/{commit}/{file}#L{span['begin'][0]}"
        out.setdefault(t["name"], []).append({"crate": short["crate"].replace("_", "-"), "path": path,
                                              "doc": t["docs"], "url": url})
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rust-repo", required=True)
    args = parser.parse_args()
    rust_repo = str(Path(args.rust_repo).resolve())
    commit = subprocess.run(["git", "-C", rust_repo, "rev-parse", "HEAD"], capture_output=True, text=True,
                            check=True).stdout.strip()
    rs = load_rust_surface(rust_repo)
    apis, handles, docs, ours = [], {}, {}, {}
    for crate in CRATES:
        doc = rustdoc(rust_repo, crate)
        short, full = surfaces(rs, doc, ours)
        apis += component_apis(crate, short, full, handles) if crate == "mpl" else esdk_apis(short, full)
        for name, found in docs_of(crate, doc, short, commit).items():
            docs.setdefault(name, []).extend(found)
    # Keep the docs of the types that an option takes, and of each handle and its components.
    named = set(handles) | {p.split("::")[-1] for h in handles.values() for p in h["members"]}
    for o in (o for a in apis for o in a["options"]):
        named |= set(re.findall(r"[A-Z]\w*", f"{o['takes']} {o.get('set_takes', '')}"))
    docs = {name: found for name, found in sorted(docs.items()) if name in named}
    OUT.write_text(json.dumps({"generated_by": "api-examples/types/rust_api.py", "rust_commit": commit,
                               "apis": apis, "handles": handles, "docs": docs}, indent=1) + "\n")
    print(f"{len(apis)} APIs, {sum(len(a['options']) for a in apis)} options at {commit[:7]}")


if __name__ == "__main__":
    main()
