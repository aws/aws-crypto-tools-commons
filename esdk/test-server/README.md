# ESDK TestServer

The ESDK TestServer is a cross-language compatibility harness for the AWS
Encryption SDK. A single Smithy model defines the client under test and a single
suite of integration Tests is written once and run against every language
implementation: the Orchestrator resolves and builds each language's Server from
its repository, launches them, and drives the same Tests over all of them. One
test case therefore checks that every ESDK language behaves identically, and a
new implementation can adopt the entire existing test suite as soon as its
Server exists.

The shared pieces — the model, the Tests, the Orchestrator, and the canonical
Configuration — live here in `aws-crypto-tools-commons`; each language's Server
lives in that language's own repository and is pulled in by the Orchestrator.
The supported servers (languages, major versions, and where each is resolved
from) are defined in [`config/server-config.json`](config/server-config.json).
To build and run the TestServer locally, see
[docs/LOCAL_DEVELOPMENT.md](docs/LOCAL_DEVELOPMENT.md); for the design of the
Configuration — the Server, Feature, and Bug config and how the Orchestrator
resolves sources — see [docs/CONFIG_DESIGN.md](docs/CONFIG_DESIGN.md).

## Running it from a language repository's CI

A language repository calls the reusable workflow; its own checkout replaces
the branch `config/server-config.json` pins for it, and every other language
resolves as configured:

```yaml
name: ESDK TestServer
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "17 7 * * *"
permissions:
  contents: read
  actions: read
  id-token: write
jobs:
  test-server:
    uses: aws/aws-crypto-tools-commons/.github/workflows/esdk-test-server-reusable.yml@main
    with:
      # Test only the pairs involving this repository's languages; omit for the
      # full matrix.
      focus: ${{ github.event_name == 'pull_request' && 'rust,rust-cpp' || '' }}
    secrets:
      # Read access to aws-crypto-tools-commons and every private language repository.
      repo-pat: ${{ secrets.COMMONS_REPO_PAT }}
```

The checkout supplies only the `checkout-languages` (default: `focus`); the
repository's other servers use their configured branches. Every other server
is fetched prebuilt: binaries are artifacts named by their key, looked up in
the calling repository and then in commons. Dependency caches are saved from
the default branch only; the scheduled run keeps them warm for pull requests.
