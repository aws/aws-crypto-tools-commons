#!/usr/bin/env python3
"""Write smithy-names.json, the Smithy names that build_api_examples.py uses for dashboard rows.

For each API it lists the Smithy input shape and its member names in model order,
the operation names (for an API that is a client method), and aliases: option
names that a language uses in place of a member name.

The models, and how a model shape maps to an API, come from aws-crypto-tools-rust's
Smithy conformance config (scripts/smithy-conformance/config.toml):
  - [smithy] and [[model]] pin the Smithy CLI and the model files.
  - An operation renamed to Type::builder or Type::new builds Type, so its input
    members are Type's options. An operation named Create<Type> with no rename
    builds Type too.
  - An operation renamed to another Type::method is a method on Type, not an API.
  - Any other operation is a client method. Its input members are the method's options.
  - A service's localService config members are the client's options.
  - A member renamed to x gives the alias x -> member.

Usage:
  smithy_names.py --conformance-config ../aws-crypto-tools-rust/scripts/smithy-conformance/config.toml \
      [--ast model.json] [--out api-examples/smithy-names.json]

--ast reads a model AST that conform.py already built (model.json in its --out
directory). Without it, the script builds one like conform.py does, caching the
Smithy CLI and model repos in ~/.cache/smithy-conformance.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

from build_api_examples import option_key

# Smithy namespace -> dashboard library.
LIBRARIES = {"aws.cryptography.materialProviders": "mpl", "aws.cryptography.encryptionSdk": "esdk"}
CONSTRUCTORS = ("builder", "new")
# The conformance tooling's Rust name for a service: its client type.
CLIENT = "Client"
CACHE = Path(os.path.expanduser(os.environ.get("SMITHY_CONFORMANCE_CACHE", "~/.cache/smithy-conformance")))


def api_id(type_name):
    """`HierarchicalKeyring` -> `hierarchical-keyring`, `RequiredEncryptionContextCMM` -> `required-encryption-context-cmm`."""
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1-\2", type_name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", s).lower()


def names(shapes, config):
    """Return {library: {api id: entry}} from a Smithy JSON AST's shapes and the conformance config."""
    renames = {r["shape"]: r["rust"] for r in config.get("rename", []) if r.get("status") != "rejected"}
    out = {lib: {} for lib in LIBRARIES.values()}

    def add(lib, api, input_sid, operations):
        if api in out[lib]:
            sys.exit(f"{lib}: two model shapes map to the API {api}")
        members = list(shapes.get(input_sid, {}).get("members", {}))
        aliases = {option_key(renames[f"{input_sid}${m}"]): m for m in members if f"{input_sid}${m}" in renames}
        out[lib][api] = {"shape": input_sid, "members": members, "operations": operations, "aliases": aliases}

    for sid, s in sorted(shapes.items()):
        lib = LIBRARIES.get(sid.split("#")[0])
        if s["type"] != "service" or lib is None:
            continue
        config_sid = s.get("traits", {}).get("aws.polymorph#localService", {}).get("config")
        if config_sid:
            add(lib, api_id(renames.get(sid, CLIENT)), config_sid, [])
        for op in s.get("operations", []):
            op_sid = op["target"]
            name = op_sid.split("#")[1]
            input_sid = shapes[op_sid].get("input", {}).get("target")
            rust = renames.get(op_sid)
            if rust and "::" in rust:
                type_name, method = rust.split("::")
                if method in CONSTRUCTORS:
                    add(lib, api_id(type_name), input_sid, [])
            elif rust is None and name.startswith("Create"):
                add(lib, api_id(name[len("Create"):]), input_sid, [])
            else:
                add(lib, api_id(rust or name), input_sid, [name])
    return out


def smithy_cli(cfg):
    version, digest = cfg["smithy"]["version"], cfg["smithy"]["sha256"]
    home = CACHE / f"smithy-cli-{version}"
    exe = home / "smithy-cli-linux-x86_64" / "bin" / "smithy"
    if exe.exists():
        return exe
    home.mkdir(parents=True, exist_ok=True)
    zpath = home / "cli.zip"
    url = f"https://github.com/smithy-lang/smithy/releases/download/{version}/smithy-cli-linux-x86_64.zip"
    urllib.request.urlretrieve(url, zpath)
    got = hashlib.sha256(zpath.read_bytes()).hexdigest()
    if got != digest:
        zpath.unlink()
        sys.exit(f"Smithy CLI checksum mismatch: got {got}, config pins {digest}")
    with zipfile.ZipFile(zpath) as z:
        z.extractall(home)
    for p in home.rglob("*"):
        if p.is_file() and ("/bin/" in p.as_posix() or "/lib/" in p.as_posix()):
            p.chmod(0o755)
    return exe


def checkout(repo, ref):
    d = CACHE / "models" / repo.rstrip("/").split("/")[-1].removesuffix(".git")
    if not (d / ".git").is_dir():
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", repo, str(d)], check=True)
    have = subprocess.run(["git", "-C", str(d), "cat-file", "-e", ref + "^{commit}"], capture_output=True)
    if have.returncode != 0:
        subprocess.run(["git", "-C", str(d), "fetch", "-q", "origin", ref], check=True)
    subprocess.run(["git", "-C", str(d), "checkout", "-q", "--detach", ref], check=True)
    return d


def build_ast(cfg):
    files = [str(checkout(m["repo"], m["ref"]) / p) for m in cfg["model"] for p in m["paths"]]
    r = subprocess.run([str(smithy_cli(cfg)), "ast", "--allow-unknown-traits", *files],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("smithy ast failed:\n" + r.stderr)
    return json.loads(r.stdout)


def main(argv=None):
    import tomllib  # Python 3.11+. Imported here so the unit tests run on older Pythons.

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--conformance-config", required=True, type=Path)
    p.add_argument("--ast", type=Path)
    p.add_argument("--out", type=Path, default=Path(__file__).with_name("smithy-names.json"))
    args = p.parse_args(argv)

    cfg = tomllib.loads(args.conformance_config.read_text())
    ast = json.loads(args.ast.read_text()) if args.ast else build_ast(cfg)
    doc = {
        "generated_by": "api-examples/smithy_names.py",
        "models": [{"repo": m["repo"], "ref": m["ref"]} for m in cfg["model"]],
        "libraries": names(ast["shapes"], cfg),
    }
    args.out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    for lib, apis in doc["libraries"].items():
        print(f"{lib}: {len(apis)} apis -> {args.out}")


if __name__ == "__main__":
    main()
