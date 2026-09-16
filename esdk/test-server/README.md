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
