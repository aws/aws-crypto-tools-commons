# Types page tools

These scripts make the data for `dashboard/api-examples/types.html`. That page shows, for each option of each ESDK and MPL API, the types a customer may hold and the code each one needs. Each type sits under the number of calls its code makes: as is, one call, more than one call, or no fix found. `calls.py` counts them. `&`, `Some(...)` and literals don't count as calls.

## CI runs everything

Nobody needs to run these by hand. Three workflows run every day, and the page loads the newest successful run of each, with the GitHub token from the dashboard's Settings:

- `api-examples-types.yml` checks out aws-crypto-tools-rust main. `rust_api.py` reads every keyring, CMM, key store, cache and client, and each of their setters, from rustdoc, into `rust-api.json`. `compile_rust_types.py` tries each held type on each option with the Rust compiler, runs the cheapest call that compiled for some options, and writes `types-rust.json`. Its artifact also has `rust_trials.rs`, one fn for each try, and `rust_runs.rs`, one test for each run. It also compiles an example of making each type, from `rust_examples.py`, and the page shows the ones that compiled.
- `api-examples-shipped.yml` reads each released Java, Python, .NET, Go and JS library. `other_languages.py` writes every API and option it finds into `types-others.json`. These calls are not compiled.
- `api-examples-usage.yml` runs `../usage_search.py`, which searches public GitHub code for calls that set each option, into `usage.json`.

So a new keyring or setter on Rust main, or in a new release of another language, shows on the page the next day. The copies of `types-rust.json`, `types-others.json` and `usage.json` in `dashboard/api-examples/` are what the page shows without a token.

A pull request in aws-crypto-tools-rust reads its own API in its own CI with `rust_api.py` and `compile_rust_types.py`, and uploads it as `api-types-rust`, and the merge base's as `api-types-rust-base`. The PR Review tab compares the two. Each option in `rust-api.json` has the lines of its setter (`span`), so that tab can tell which option a changed line belongs to. The types page shows a Rust pull request's API when `?pr=` or the dashboard's shared PR box names one. `?api=mpl|aws-kms-keyring` opens one API.

## What people write

- `rust-types.json`, the Rust types customers hold. `python3 rust_types.py build` makes it from the 174 crates pinned in `rust-types.lock.json`, and `python3 rust_types.py refresh --rust-repo <checkout>` picks new crates. For each type, it gives how many crates use it, names three of them, and lists the rules it used. An optional type is kept only when the type inside it is held on its own.
- The other languages' types, and how to convert each one, in `other_languages.py`.
- `dashboard/api-examples/expectations.json`, rules about what an option should not take as is, like text for a wrapping key. The page marks each type that breaks a rule with ⚠.

## Running them locally

From this folder, with an aws-crypto-tools-rust checkout and the nightly toolchain:

1. `python3 rust_api.py --rust-repo <checkout>`
2. `python3 compile_rust_types.py --rust-repo <checkout>`
3. `python3 other_languages.py --shipped <folder>`, where the folder holds the `api-examples-*-shipped` artifacts, which `gh run download` can fetch.

## Proposed signatures

The page has no proposals of its own. The `api-signature-proposals` skill in CryptoToolsAISkills writes them, because choosing a signature takes judgment. Then `python3 check_proposals.py --input <proposals file> --rust-repo <checkout>` compiles every held type against each Rust proposal. It lists the calls that would stop compiling, and writes `dashboard/api-examples/proposals.json`. Git ignores that file. The page shows it when it sits next to the page, or when you open it with the Load proposals button.

## Tests

From the repository root, `python3 -m unittest discover -s api-examples/types` tests these scripts. `node --test dashboard/api-examples/types.test.js` tests the page, and checks that each committed Rust row links to its own trial and test.
