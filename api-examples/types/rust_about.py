"""What each Rust type on the types page is, and where a customer gets one.

The page shows this when someone clicks a type. A type is explained one part at a time: Option<&AppName>
is Option, & and AppName. A standard library part gets a short line from STD, written for this page, and a
link to its docs. Any other part quotes the start of its doc comment, which rust_types.py read from the
crate's source, and links to the line where the crate defines it.
"""
import re

STD_DOCS = "https://doc.rust-lang.org/std/"
# Each standard library part: what it is, in plain words, and its docs page under STD_DOCS.
STD = {
    "&": ("Borrowed. You can read it, but something else owns it.", "primitive.reference.html"),
    "[]": ("Several values in a row, like part of a list.", "primitive.slice.html"),
    "[; N]": ("Exactly {n} values in a row.", "primitive.array.html"),
    "()": ("Two values side by side.", "primitive.tuple.html"),
    "Option": ("A value, or nothing.", "option/enum.Option.html"),
    "Vec": ("A list that can grow. It owns its items.", "vec/struct.Vec.html"),
    "String": ("Text that you own and can change.", "string/struct.String.html"),
    "str": ("Text. You usually borrow it, as &str.", "primitive.str.html"),
    "char": ("One character, like 'a'. Not a whole string.", "primitive.char.html"),
    "Box": ("Owns one value, kept in its own spot in memory.", "boxed/struct.Box.html"),
    "Arc": ("A value that many owners share, even across threads. They can read it but not change it.",
            "sync/struct.Arc.html"),
    "Rc": ("A value that many owners on one thread share. They can read it but not change it.", "rc/struct.Rc.html"),
    "Cow": ("Either borrows a value or owns it. It copies the value only if you change it.",
            "borrow/enum.Cow.html"),
    "HashMap": ("A lookup table from keys to values.", "collections/struct.HashMap.html"),
    "BTreeMap": ("A lookup table from keys to values, sorted by key.", "collections/struct.BTreeMap.html"),
    "Path": ("A file path. You usually borrow it, as &Path.", "path/struct.Path.html"),
    "PathBuf": ("A file path that you own.", "path/struct.PathBuf.html"),
    "File": ("An open file.", "fs/struct.File.html"),
    "TcpStream": ("An open network connection.", "net/struct.TcpStream.html"),
    "Duration": ("A span of time, like 5 seconds.", "time/struct.Duration.html"),
    "u8": ("A whole number from 0 to 255. One byte.", "primitive.u8.html"),
    "u16": ("A whole number from 0 to 65,535.", "primitive.u16.html"),
    "u32": ("A whole number from 0 to 4,294,967,295.", "primitive.u32.html"),
    "u64": ("A whole number from 0 to 2^64 - 1.", "primitive.u64.html"),
    "u128": ("A whole number from 0 to 2^128 - 1.", "primitive.u128.html"),
    "usize": ("A whole number from 0 up, as big as a memory address: 2^64 - 1 on most machines.",
              "primitive.usize.html"),
    "i8": ("A whole number from -128 to 127.", "primitive.i8.html"),
    "i16": ("A whole number from -32,768 to 32,767.", "primitive.i16.html"),
    "i32": ("A whole number from -2,147,483,648 to 2,147,483,647.", "primitive.i32.html"),
    "i64": ("A whole number from -2^63 to 2^63 - 1.", "primitive.i64.html"),
    "i128": ("A whole number from -2^127 to 2^127 - 1.", "primitive.i128.html"),
    "isize": ("A whole number, positive or negative, as big as a memory address.", "primitive.isize.html"),
}
STD_CRATES = ("std::", "core::", "alloc::")
# What each list in rust-types.json holds, for "8 of the 26 AWS SDK crates".
LIST_NAMES = {"rust": "most-downloaded crates", "aws": "AWS SDK crates", "crypto": "crypto crates"}


def tokens(t):
    """The parts of a type, in order: "&", "[]" for a slice, "[; 32]" for an array, "()" for a tuple, or a path."""
    out = []
    for m in re.finditer(r"&|\[|\(|(?:\w+::)*[A-Za-z_]\w*", t):
        tok = m.group()
        if tok == "[":
            depth, end = 0, m.start()
            for end in range(m.start(), len(t)):
                if t[end] in "[<(":
                    depth += 1
                elif t[end] in "]>)":
                    depth -= 1
                if depth == 0:
                    break
            size = re.search(r";\s*(\d+)$", t[m.start() + 1:end])
            out.append(f"[; {size.group(1)}]" if size else "[]")
        elif tok == "(":
            out.append("()")
        else:
            out.append(tok)
    return out


def std_part(key, shown, n=None):
    text, page = STD[key]
    return {"name": shown, "text": text.format(n=n), "url": STD_DOCS + page}


def parts(label, expr, docs):
    """Each part of a type once, as {name, text, url}, plus "from" for a quote from a crate's docs.

    label is the type as the page shows it, like kms::Client. expr is the same type with full paths, like
    aws_sdk_kms::Client, which says which crate each name comes from. docs is rust-types.json's docs.
    """
    out, seen = [], set()
    for shown, path in zip(tokens(label), tokens(expr)):
        name = path.split("::")[-1]
        if shown in seen:
            continue
        seen.add(shown)
        if shown in ("&", "[]", "()"):
            out.append(std_part(shown, {"&": "&", "[]": "[ ]", "()": "( , )"}[shown]))
        elif shown.startswith("[;"):
            n = shown[3:-1]
            out.append(std_part("[; N]", f"[ ; {n}]", n))
        elif name in STD and ("::" not in path or path.startswith(STD_CRATES)):
            out.append(std_part(name, shown))
        else:
            crate = path.split("::")[0].replace("_", "-") if "::" in path else None
            found = [d for d in docs.get(name, []) if crate is None or d["crate"].replace("_", "-") == crate]
            if not found:
                out.append({"name": shown, "text": "", "url": None})
                continue
            d = found[0]
            # Our own crates' docs, from rust_api.py, link to the source on GitHub. The rest link to docs.rs.
            url = d.get("url") or f"https://docs.rs/crate/{d['crate']}/{d['version']}/source/{d['file']}#{d['line']}"
            source = f"{d['crate']} {d['version']}" if d.get("version") else d["crate"]
            out.append({"name": shown, "text": d["doc"], "from": source, "url": url})
    return out


def held(row, sizes):
    """Where a customer gets a type: how many crates in each list hand one out, and links to some of them.

    row is the type's row in rust-types.json. sizes is the number of crates in each list.
    """
    counts = [f"{row[f'{name}_crates']} of the {sizes[name]} {LIST_NAMES[name]}" for name in LIST_NAMES
              if row.get(f"{name}_crates")]
    if not counts:
        return None
    text = ", ".join(counts[:-1]) + (" and " if len(counts) > 1 else "") + counts[-1]
    return {
        "text": f"{text} return one or have one as a public field.",
        "why": row.get("why"),
        "examples": [{"crate": e["crate"], "item": e["item"], "pos": e["pos"],
                      "url": f"https://docs.rs/crate/{e['crate']}/{e['version']}/source/{e['file']}#{e['line']}"}
                     for e in row.get("examples", [])],
    }


def about(held_types, rust_types, docs, sizes):
    """{label: {parts, held}} for every Rust type on the page.

    held_types is {option: [(label, Rust type with full paths, kind, fixes)]} from compile_rust_types.prepare.
    """
    rows = {r["type"]: r for found in rust_types["kinds"].values() for r in found}
    out = {}
    for found in held_types.values():
        for label, expr, kind, _ in found:
            # A pair's Rust type is its element's, because x and y each hold one.
            entry = {"parts": parts(label, f"({expr}, {expr})" if kind == "pair" else expr, docs)}
            if label in rows and held(rows[label], sizes):
                entry["held"] = held(rows[label], sizes)
            out[label] = entry
    return dict(sorted(out.items()))
