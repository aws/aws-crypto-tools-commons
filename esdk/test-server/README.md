# ESDK TestServer — local development

This is the developer guide for building and running the ESDK TestServer on your
machine. It covers the fast inner loop (no clones, no AWS credentials), the full
cross-language run, and how to iterate on a single Language_Server with your
local edits used live.

For the design (Configuration organization, the resolution pipeline, the
Server/Feature/Bug config files) see the design doc; this README is only about
the local workflow.

## Layout

The TestServer is a set of **separate** Gradle builds (not a composite build),
each with its own wrapper, plus the commons-owned config:

| Module | What it is |
|---|---|
| `model/` | the single Smithy model |
| `client-java/` | the generated Java Test_Client |
| `tests/` | the single Java Tests suite |
| `orchestrator/` | the Orchestrator core (resolves, builds, launches, runs, reports) |
| `config/` | the commons Configuration_Set: `server-config.json`, `feature-set.json`, `bug-list.json` |

The Java (and other language) servers are **not** hosted here — they live in
their Language_Repositories and are resolved by the orchestrator from
`config/server-config.json`.

## Prerequisites

- **JDK 21+** (smithy-java requires it). Either export `JAVA_HOME`, pass
  `make JAVA_HOME=/path/to/jdk21 <target>`, or rely on the Makefile's
  auto-detection. Verify with `make check-java`.
- **git**, and **python3** (used by the structural smoke checks in `make validate`).
- **AWS credentials** are required *only* for `make orchestrate` (the KMS
  keyring scenarios are part of it). The inner-loop targets below need none.

> On NFS home directories, Gradle's file-watcher can throw
> `java.io.IOException: Function not implemented`. If you hit it, disable the
> watcher: `export GRADLE_OPTS=-Dorg.gradle.vfs.watch=false` (or pass
> `--no-watch-fs` to a direct `./gradlew` invocation).

## The fast inner loop (no clones, no credentials)

Every one of these `cd`s into a single module and runs that module's own build —
none of them clone a Language_Repository or need AWS credentials:

```
make build            # compile/codegen the client + Tests (skips tests)
make build-client     # just the Java Test_Client
make build-tests      # just the Tests suite
make validate         # smithy validate + structural smoke checks
make smoke            # model smoke checks + Tests round-trip smoke check
make orchestrate-test # the orchestrator's own property/integration tests
```

`make orchestrate-test` is the one to run while working on the orchestrator
itself — it exercises the resolution/materialization/validation pipeline as pure
logic, with no git and no network.

## The full cross-language run

```
make orchestrate      # resolve + build + launch every configured server, run the full matrix
```

This is a **Commons_Run**: it reads `config/` from your commons working tree and
resolves *every* language's server from `server-config.json`. It runs the whole
pairwise `(encrypt, decrypt)` matrix and the required KMS scenarios, so it needs
valid AWS credentials (e.g. run `creds`) and is heavyweight for a quick loop.
Point it at a non-default KMS key set with the `ESDK_TESTSERVER_KMS_*` env vars
(see the Makefile header).

### It does not clone from scratch every time

Source materialization reuses work across runs:

- **Working-tree sources are never cloned.** (See the next section.)
- **Clones are cached and deduplicated.** Each distinct `(url, ref)` is cloned
  once into `orchestrator/build/` scratch. On the next run, an existing scratch
  clone is **reused in place** when its local `HEAD` still equals the live
  remote tip of the branch; it is only wiped and re-cloned when it is absent,
  not a repo, or the tip has moved. Components sharing `(url, ref)` share one
  clone.

So the scratch clones survive between runs (until `make clean` or a
`./gradlew clean`), and unchanged branches are not re-fetched. Note the reuse
check does a per-run `git ls-remote`, so a fully offline run can only reuse
working-tree sources — cloned languages need the network to verify the tip.

## Iterating on a single Language_Server with live edits

To develop a server and have **your local, uncommitted edits used directly**
(not a clone), run the orchestrator in **`language:<lang>`** mode from that
language's checkout. In that mode the *own* language's library and server
resolve to your working tree — the configured ref is ignored and nothing is
cloned for it (a dirty tree is used as-is and reported as dirty). Every *other*
language, plus the commons Tests, are cached clones as described above.

Run it directly (there is no dedicated Make target yet), from `orchestrator/`:

```
cd orchestrator
./gradlew --console=plain run --args="\
  context=language:rust \
  languageRepoRoot=/abs/path/to/aws-crypto-tools-rust \
  commonsOrigin.url=git@github.com:aws/aws-crypto-tools-commons.git \
  commonsOrigin.branch=main \
  commonsOrigin.reason=configuration-entry"
```

- `context=language:<lang>` — the language whose working tree you are editing.
- `languageRepoRoot=<abs path>` — your local checkout of that language repo; its
  library and server are used live from here.
- `commonsOrigin.url` / `commonsOrigin.branch` — where the shared Tests + catalog
  come from. Tip: for an offline/local commons, a local path or `file://` URL to
  your commons checkout works as the clone source (it is copied, not edited
  live — to edit the **Tests** live, use `make orchestrate`, a Commons_Run,
  which uses the commons working tree directly).
- `invokingRepositoryName` defaults to `aws-crypto-tools-<lang>`; override it
  only if your repo has a different canonical name.

**Sibling servers in the same repo (monorepo):** any server whose
`serverLocation.repository` equals the invoking repository is *also* used from
the invoking working tree. So when you run from a monorepo checkout (e.g.
`aws-encryption-sdk`, which hosts the `net`/`rust`/`go` servers), all of its
sibling servers are live from your tree, not cloned — set `languageRepoRoot`
and `invokingRepositoryName` to that repo.

### Editing a language in a *different* repo than the one you run from

Use the **local-overrides overlay** — a dev-only file mapping a language to a
local working-tree root the orchestrator uses in place of a clone. Drop a
`config/local-overrides.json` (gitignored — it never ships in committed config):

```json
{
  "repositories": {
    "rust": "/abs/path/to/aws-crypto-tools-rust",
    "javascript": "/abs/path/to/aws-encryption-sdk-javascript"
  }
}
```

Each value is that language's local repo root; its library and server are used
live from your tree (uncommitted edits and all), while every other language is
still a cached clone. Then run the normal cross-language run — no extra flags:

```
make orchestrate     # auto-loads config/local-overrides.json when present
```

`make orchestrate` (a Commons_Run) picks the overlay up automatically; the
Resolution_Record marks those components with reason `local-override`. To keep
the overlay elsewhere, pass `localOverrides=<path>` to the orchestrator
(`./gradlew run --args="... localOverrides=/abs/path/to/overlay.json"`).

The overlay applies to any language **except** the own language of a
`context=language:<lang>` run (already your working tree), and it **wins over** a
`configurationOverrides` clone. Copy `config/local-overrides.example.json` to
get started. Relative paths in the overlay resolve against the overlay file's
own directory.

This makes iterating on two or more languages in different repos
simultaneously — with live edits on each — a first-class flow: list them all in
the overlay and run `make orchestrate`.

If you'd rather not use a local checkout, you can still **push to a branch and
pin the ref** in that language's `server-config.json` (or a
`configurationOverrides` entry) — clone-based, so it picks up pushed commits,
not local working-tree edits.

## Local overrides are dev-only

The local-overrides overlay exists purely for local development. `local-overrides.json`
is gitignored and must never be committed — CI never sees it, so committed
configuration always resolves every non-own language from a clone. The overlay
only turns a language's source into a working-tree plan; the component paths
still come from that language's configuration entry.

## Cleaning up

```
make clean            # gradle clean in every module + remove scratch
```

Scratch clones live under `orchestrator/build/`; removing that directory forces
fresh clones on the next orchestrated run.
