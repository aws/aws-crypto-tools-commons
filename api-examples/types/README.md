# Types page tools

These scripts make the data for `dashboard/api-examples/types.html`. That page shows, for each option, the types a customer may hold and the code each one needs. Each type sits under the number of calls its code makes: as is, one call, more than one call, or no fix found. `calls.py` counts them. `&`, `Some(...)` and literals don't count as calls.

To update the page, run these from this folder, in order:

0. `python3 rust_api.py --rust-repo <aws-crypto-tools-rust checkout>` reads every keyring, CMM, key store, cache and client, and each of their setters, from rustdoc, and writes `rust-api.json`. It needs the nightly toolchain. Run it after the Rust API changes, like a new keyring or setter, and the page shows the new one with every type.
1. `python3 rust_types.py refresh --rust-repo <aws-crypto-tools-rust checkout>` asks crates.io which crates to read and pins them in `rust-types.lock.json`. Skip this step to keep the same crates.
2. `python3 rust_types.py build` downloads the pinned crates, checks their checksums, reads their public signatures with `rust-scan`, and writes `rust-types.json`. The same lock always gives the same output.
3. `python3 compile_rust_types.py --rust-repo <aws-crypto-tools-rust checkout>` tries each type on each option with the Rust compiler, and runs the cheapest call that compiled. It writes the Rust rows into the page data, and the code it compiled and ran:
   - `rust_trials.rs` has one fn for each try. The page links each Rust type to the fn that compiled.
   - `rust_runs.rs` has one test for each call that compiled. The test holds the option's value in that type, passes it, and finishes the build or the encrypt. It records whether that worked and whether the result matches the reference value. For plaintext and ciphertext, it also records whether passing the value copied it. `rust_runs_support.rs` has the reference values and the checks. The KMS and Hierarchical keyrings are only checked through their getters, because the tests have no AWS access.
4. `python3 other_languages.py --shipped <folder>` writes the rows for the other languages. The folder holds the `api-examples-*-shipped` artifacts from a run of `api-examples-shipped.yml`, which `gh run download` can fetch. These calls are not compiled.

`rust-types.json` lists the rules it used. For each type, it gives how many crates use it and names three of them.

The `API examples types` workflow (`.github/workflows/api-examples-types.yml`) runs step 3 again on the aws-crypto-tools-rust commit and the rustc version that `types.json` names. It fails when the results differ from the committed ones.

## Rules

`dashboard/api-examples/expectations.json` holds rules that a person wrote about what an option should not take as is, like text for a wrapping key. The page marks each type that breaks a rule with ⚠, in every language.

## Customer code

`../usage_search.py` searches public GitHub code for calls that set each option, and writes `dashboard/api-examples/usage.json`. The page lists every hit under Compare languages, with its line of code and a link. Hits in one file, or in copies of one file, count as one source. Copies of AWS code, like AWS Lambda Powertools, are listed but not counted.

## Proposed signatures

The page has no proposals of its own. The `api-signature-proposals` skill in CryptoToolsAISkills writes them, because choosing a signature takes judgment. Then `python3 check_proposals.py --input <proposals file> --rust-repo <aws-crypto-tools-rust checkout>` compiles every held type against each Rust proposal. It lists the calls that would stop compiling, and writes `dashboard/api-examples/proposals.json`.

Git ignores `proposals.json`. The page shows it when it sits next to `types.json`. On another machine, use the page's Load proposals button to open the file. The file also holds its own input, so it can be checked again.

## Tests

From the repository root, `python3 -m unittest discover -s api-examples/types` tests these scripts. `node --test dashboard/api-examples/types.test.js` tests the page, and checks that each committed Rust row links to its own trial and test.
