"""An example of making each Rust type that the types page shows, like `let x: Cow<str> = Cow::Borrowed("my text");`.

compile_rust_types.py compiles each example, and the page shows only the ones that compiled. An example
names types the way a customer writes them, after the `use` lines it lists.
"""
import re

# Where each name that an example uses lives. Our own types come from rust-api.json, in uses().
STD_USES = {
    "Cow": "std::borrow::Cow", "Arc": "std::sync::Arc", "HashMap": "std::collections::HashMap",
    "Path": "std::path::Path", "PathBuf": "std::path::PathBuf", "File": "std::fs::File",
    "TcpStream": "std::net::TcpStream", "Duration": "std::time::Duration", "Bytes": "bytes::Bytes",
    "Blob": "aws_smithy_types::Blob", "ByteStream": "aws_smithy_types::byte_stream::ByteStream",
    "SdkBody": "aws_smithy_types::body::SdkBody", "Zeroizing": "zeroize::Zeroizing",
}
TEXT = '"my text"'
NUMBERS = {"u8": "64", "i8": "64", "u16": "4096", "i16": "4096"}
# An expression that makes each owned type. {text} is a string literal.
OWNED = {
    "String": "String::from({text})",
    "Cow<str>": "Cow::Borrowed({text})",
    "Box<str>": "Box::from({text})",
    "Zeroizing<String>": "Zeroizing::new(String::from({text}))",
    "char": "'m'",
    "Vec<u8>": 'b"my bytes".to_vec()',
    "[u8; 32]": "[7u8; 32]",
    "Box<[u8]>": 'Box::from(&b"my bytes"[..])',
    "Bytes": 'Bytes::from_static(b"my bytes")',
    "Blob": 'Blob::new(b"my bytes".to_vec())',
    "ByteStream": 'ByteStream::from(b"my bytes".to_vec())',
    "SdkBody": 'SdkBody::from("my bytes")',
    "PathBuf": 'PathBuf::from("data.txt")',
    "File": 'File::open("data.txt")?',
    "TcpStream": 'TcpStream::connect("example.com:443")?',
    "Duration": "Duration::from_secs(300)",
    "Vec<String>": "vec![String::from({text})]",
    "HashMap<String, String>": 'HashMap::from([(String::from("purpose"), String::from("test"))])',
    "SdkConfig": "aws_config::load_from_env().await",
    "kms::Client": "aws_sdk_kms::Client::new(&aws_config::load_from_env().await)",
    "kms::Config": "aws_sdk_kms::Config::from(&aws_config::load_from_env().await)",
    "dynamodb::Client": "aws_sdk_dynamodb::Client::new(&aws_config::load_from_env().await)",
    "dynamodb::Config": "aws_sdk_dynamodb::Config::from(&aws_config::load_from_env().await)",
}
# A borrowed type a literal can be, as is.
BORROWED = {"&str": TEXT, "&[u8]": 'b"my bytes"', "&Path": 'Path::new("data.txt")', "&[&str]": "&[\"my text\"]"}
KEY_ARN = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
# How to build each of our components, and our other types that take code to make, ending with x. A line like
# "@DynamoDbKeyStore key_store" is that type's lines, making key_store.
COMPONENTS = {
    "KmsConfiguration": [f'let x = KmsConfiguration::kms_key_arn("{KEY_ARN}");'],
    "RawAesKeyring": ["let x = RawAesKeyring::builder()", '    .key_namespace("my-namespace")', '    .key_name("my-key")',
                      "    .wrapping_key(vec![7u8; 32])", "    .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)",
                      "    .build()?;"],
    "AwsKmsKeyring": ["let x = AwsKmsKeyring::builder()", f'    .kms_key_id("{KEY_ARN}")',
                      "    .kms_client(aws_sdk_kms::Client::new(&aws_config::load_from_env().await))",
                      "    .build()?;"],
    "DynamoDbKeyStore": ["let config = aws_config::load_from_env().await;", "let x = DynamoDbKeyStore::builder()",
                         '    .ddb_table_name("KeyStoreTable")', '    .logical_key_store_name("KeyStoreTable")',
                         f'    .kms_configuration(KmsConfiguration::kms_key_arn("{KEY_ARN}"))',
                         "    .kms_client(aws_sdk_kms::Client::new(&config))",
                         "    .ddb_client(aws_sdk_dynamodb::Client::new(&config))", "    .build()?;"],
    "HierarchicalKeyring": ["@DynamoDbKeyStore key_store", "let x = HierarchicalKeyring::builder()",
                            "    .key_store(key_store)", '    .branch_key_id("my-branch-key-id")',
                            "    .ttl(Duration::from_secs(300))", "    .build()?;"],
    "DefaultCmm": ["@RawAesKeyring keyring", "let x = DefaultCmm::new(keyring);"],
    "DefaultCmc": ["let x = DefaultCmc::builder()", "    .entry_capacity(100)", "    .build()?;"],
    "LocalCmc": ["let x = LocalCmc::builder()", "    .entry_capacity(100)", "    .build()?;"],
    "StormTrackingCmc": ["let x = StormTrackingCmc::builder()", "    .entry_capacity(100)", "    .build()?;"],
    "SharedKeyring": ["@RawAesKeyring keyring", "let x = SharedKeyring::new(keyring);"],
    "SharedCmm": ["@DefaultCmm cmm", "let x = SharedCmm::new(cmm);"],
    "SharedKeyStore": ["@DynamoDbKeyStore key_store", "let x = SharedKeyStore::new(key_store);"],
    "SharedCmc": ["@DefaultCmc cache", "let x = SharedCmc::new(cache);"],
}


def component(name, var="x"):
    """A component's lines, with each @Other line replaced by Other's lines, and x renamed to var."""
    out = []
    for line in COMPONENTS[name]:
        if line.startswith("@"):
            other, other_var = line[1:].split()
            out += component(other, other_var)
        else:
            out.append(re.sub(r"^let x\b", f"let {var}", line))
    return out


def owned(t, text=TEXT):
    """An expression that makes the owned type t, or None."""
    if t in OWNED:
        return OWNED[t].format(text=text)
    if t in NUMBERS or re.fullmatch(r"[ui](8|16|32|64|128|size)", t):
        return f"{NUMBERS.get(t, '4096')}{t}"
    return None


def example(label, enums):
    """The lines that make x hold `label`, or None when there is no example.

    enums maps each of our enums to its first variant without a payload, like AesWrappingAlg to
    AlgAes256GcmIv12Tag16.
    """
    if label in BORROWED:
        return [f"let x: {label} = {BORROWED[label]};"]
    if label in COMPONENTS:
        return component(label)
    if label in enums:
        return [f"let x = {label}::{enums[label]};"]
    if label.startswith("&") and label[1:] in COMPONENTS:
        return component(label[1:], "value") + ["let x = &value;"]
    if label.startswith("Arc<") and label[4:-1] in COMPONENTS:
        return component(label[4:-1], "value") + ["let x = Arc::new(value);"]
    if label.startswith("&") and (label[1:] in enums):
        return [f"let value = {label[1:]}::{enums[label[1:]]};", "let x = &value;"]
    pair = re.fullmatch(r"\((.+), \1\)", label)
    if pair:
        t = pair.group(1)
        if t in BORROWED:
            return [f'let (x, y): ({t}, {t}) = ("purpose", "test");']
        owned_t = t.lstrip("&")
        key, value = owned(owned_t, '"purpose"'), owned(owned_t, '"test"')
        if key is None:
            return None
        if t.startswith("&"):
            return [f"let (key, value) = ({key}, {value});", "let (x, y) = (&key, &value);"]
        return [f"let (x, y) = ({key}, {value});"]
    inner = re.fullmatch(r"Option<(.+)>", label)
    if inner:
        lines = example(inner.group(1), enums)
        if not lines:
            return None
        # The inner value's last line becomes Some(...), and a borrow keeps its owner.
        *setup, last = lines
        value = re.fullmatch(r"let x(?:: [^=]+)? = (.+);", last)
        return setup + [f"let x: {label} = Some({value.group(1)});"] if value else None
    if label == "&String":
        return [f"let value = String::from({TEXT});", "let x = &value;"]
    if label == "&[String]":
        return [f"let value = vec![String::from({TEXT})];", "let x: &[String] = &value;"]
    if label.startswith("Arc<"):
        made = owned(label[4:-1])
        return [f"let x = Arc::new({made});"] if made else None
    if label.startswith("&"):
        made = owned(label[1:])
        return [f"let value = {made};", "let x = &value;"] if made else None
    made = owned(label)
    if made is None:
        return None
    # A literal or a generic constructor needs the type said out loud.
    typed = label in ("Cow<str>", "Box<str>", "Box<[u8]>") or re.fullmatch(r"[ui]\w+", label)
    return [f"let x: {label} = {made};" if typed else f"let x = {made};"]


def uses(lines, ours):
    """The use lines an example needs: one for each name in it that is not in the prelude.

    ours maps each of our own type names to its path, from rust-api.json.
    """
    text = "\n".join(lines)
    found = {path for name, path in {**STD_USES, **ours}.items() if re.search(rf"(?<![\w:]){name}\b", text)}
    return [f"use {path};" for path in sorted(found)]


def check_line(n, lines, use, expr):
    """One line that compiles an example: an async fn that makes x, then checks that x has the type expr."""
    body = " ".join(use + [line.strip() for line in lines])
    check = f"let _check: ({expr}, {expr}) = (x, y);" if " (x, y)" in body or "let (x, y)" in body else f"let _check: {expr} = x;"
    return f"async fn e{n}() -> Result<(), Box<dyn std::error::Error>> {{ {body} {check} Ok(()) }}"
