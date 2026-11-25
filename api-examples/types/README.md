# Types page tools

These scripts make the data for `dashboard/api-examples/types.html`. That page shows, for each option, the types a customer may hold and the code each one needs.

To update the page, run these from this folder, in order:

1. `python3 rust_types.py refresh --rust-repo <aws-crypto-tools-rust checkout>` asks crates.io which crates to read and pins them in `rust-types.lock.json`. Skip this step to keep the same crates.
2. `python3 rust_types.py build` downloads the pinned crates, checks their checksums, reads their public signatures with `rust-scan`, and writes `rust-types.json`. The same lock always gives the same output.
3. `python3 compile_rust_types.py --rust-repo <aws-crypto-tools-rust checkout>` tries each type on each option with the Rust compiler and writes the Rust rows into the page data.
4. `python3 other_languages.py --shipped <folder>` writes the rows for the other languages. The folder holds the `api-examples-*-shipped` artifacts from a run of `api-examples-shipped.yml`, which `gh run download` can fetch. These calls are not compiled.

`rust-types.json` lists the rules it used. For each type, it gives how many crates use it and names three of them.

## Proposed signatures

The page has no proposals of its own. The `api-signature-proposals` skill in CryptoToolsAISkills writes them, because choosing a signature takes judgment. Then `python3 check_proposals.py --input <proposals file> --rust-repo <aws-crypto-tools-rust checkout>` compiles every held type against each Rust proposal. It lists the calls that would stop compiling, and writes `dashboard/api-examples/proposals.json`.

Git ignores `proposals.json`. The page shows it when it sits next to `types.json`. On another machine, use the page's Load proposals button to open the file. The file also holds its own input, so it can be checked again.
