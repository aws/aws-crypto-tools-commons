# ESDK TestServer — Tests (single suite) and how to run the blob round-trip

This module holds **the single `Tests` definition** (Requirement 7.1). It drives every
`Language_Server` exclusively through the **one** generated Java `Test_Client`
(Requirement 1.6). Which endpoint(s) the Tests target comes from **runtime configuration
only** (Requirement 7.3) — pointing the suite at a different server is a config change with
no change to the Tests.

The first-pass Test is the **blob round-trip**: `CreateClient` on each endpoint of a pair,
`Encrypt` on one, `Decrypt` on the other, assert the recovered plaintext is byte-for-byte
identical to the original (Requirements 4.2, 4.3, 4.4, 4.8). It uses a fully offline
**Raw-AES** keyring, so there are **no KMS/network calls**.

The round-trip runs over the **real rpcv2Cbor wire protocol over HTTP**:

```
generated Java Test_Client  ──HTTP (rpcv2Cbor)──▶  Java Language_Server  ──▶  real AWS ESDK for Java
```

## Prerequisites

- **JDK 21+** is required by smithy-java. Set `JAVA_HOME` to a JDK 21+ install, e.g.:
  ```bash
  export JAVA_HOME=/opt/homebrew/Cellar/openjdk/23.0.2/libexec/openjdk.jdk/Contents/Home
  ```
  (A default Corretto 17 will fail to build smithy-java.)

## Option A — Orchestrated (recommended): the orchestrator launches the servers

The Tests are **endpoint-only** (Requirement 10.2): they never boot a server themselves.
The orchestrated entry point (`make orchestrate`, from the TestServer root) launches every
configured `Language_Server` as a subprocess and runs the Tests with the
`dbesdk.testserver.targets` property set. With targets configured, the suite runs:

- `MaterialsRoundTripTests` — the single per-configuration class; a blob (`blob[...]`) and a
  stream (`stream[...]`) `@ParameterizedTest`, each run against every offline scenario in
  `EsdkClientConfigs.scenarios()` as its own named execution (Tasks 14.1, 14.3)
- `BlobRoundTripPropertyTest` — Property 1, jqwik, 100 iterations, arbitrary/empty/binary/large
  plaintext (Task 5.3)
- `StreamRoundTripPropertyTest` — Property 15, jqwik, 100 iterations, arbitrary/empty/binary/large
  plaintext (Task 14.2)

## Option B — Manual two-step: start Language_Server(s), then run the Tests against them

Start each server yourself (for example the Java server via `./gradlew runServer
--args="9090"` in its server directory, or the Python server via
`python -m esdk_test_server 9092`), then run the Tests from this `tests/` directory,
pointing them at the running endpoints:

```bash
JAVA_HOME=<jdk21+> ./gradlew test \
  -Desdk.testserver.targets=java:3=http://127.0.0.1:9090,python:4=http://127.0.0.1:9092
```

Stop the servers with Ctrl-C when done.

### Runtime target configuration (Requirements 7.3, 10.2)

The suite reads its targets, in precedence order, from:

1. system property `dbesdk.testserver.targets`
2. environment variable `DBESDK_TESTSERVER_TARGETS`

The value is a comma-separated list of `<language>:<majorVersion>=<endpointUrl>` entries,
e.g. `java:3=http://127.0.0.1:8091,python:4=http://127.0.0.1:8092`. The cross-language
matrix is the full pairwise (encrypt, decrypt) product of the targets, including
same-target pairs. **When no targets are configured the Tests fail with an actionable
message** — there is no managed (in-process) fallback and no legacy
`dbesdk.testserver.endpoints` property. Meta (harness-plumbing) tests run against the
primary (first) configured target.

## Online AWS KMS keyring scenarios (credential-gated, Requirement 14)

The KMS keyring variants — `AwsKms` (single symmetric key), `AwsKmsMrk` (multi-region key),
`AwsKmsMultiKeyring`, `AwsKmsMrkMultiKeyring` (two multi-region keys: generator + child),
`AwsKmsRsa` (asymmetric RSA key), and `AwsKmsDiscovery` — are exercised
by the **same** `MaterialsRoundTripTests` mechanism as the offline scenarios: each becomes a
named `blob[awsKms]` / `stream[awsKmsMrk]` / … execution. Unlike the offline Raw-AES/Raw-RSA
scenarios, these are **online**: they make real AWS KMS calls on encrypt/decrypt, so they
require **AWS credentials** and network access.

They are **required**: the KMS scenarios are always contributed to
`EsdkClientConfigs.scenarios()` and always run against the `KMS_Test_Resources` (whose ARNs
default — see below — so no configuration is needed to target the shared keys). They appear
in the report as `blob[awsKms]`, `stream[awsKmsMrk]`, … , and **a run does not pass unless
they run and pass** (Requirements 14.8, 14.9). There is no offline skip: `make test`,
`make orchestrate`, and CI all require **AWS credentials** (developer credentials locally,
GitHub OIDC in CI). Without usable credentials the KMS scenarios fail and the run fails.

Only the arbitrary-plaintext property tests (`BlobRoundTripPropertyTest`,
`StreamRoundTripPropertyTest`) are credential-free: they draw from
`EsdkClientConfigs.offlineScenarios()` and never touch KMS.

### KMS runtime configuration (Requirement 14.7)

The KMS key ARNs and region are read in precedence order system property, then environment
variable, then a **built-in default** — the ARNs of the shared `KMS_Test_Resources` the
`cdk/` stack deploys into the CI-resources account. Those defaults are KMS key ARNs, not
secrets (their use is still gated by AWS credentials), so a developer or CI job with
credentials for that account needs no extra configuration; override them when deploying the
stack into a different account:

| System property | Environment variable | Meaning |
|---|---|---|
| `dbesdk.testserver.kms.symmetricKeyArn` | `DBESDK_TESTSERVER_KMS_SYMMETRIC_KEY_ARN` | symmetric KMS key → `AwsKms` |
| `dbesdk.testserver.kms.mrkArn` | `DBESDK_TESTSERVER_KMS_MRK_ARN` | multi-region KMS key → `AwsKmsMrk` |
| `dbesdk.testserver.kms.rsaKeyArn` | `DBESDK_TESTSERVER_KMS_RSA_KEY_ARN` | asymmetric RSA KMS key → `AwsKmsRsa` |
| `dbesdk.testserver.kms.region` | `DBESDK_TESTSERVER_KMS_REGION` | AWS region (default `us-west-2`) |

The default ARNs are the CDK `EsdkTestServerKmsStack` `CfnOutput`s (`symmetricKeyArn`,
`mrkArn`, `rsaKeyArn`); a fresh deploy into another account prints new ones to override with.

### Running the KMS scenarios locally

The KMS scenarios are required, so `make test` runs them against the default
`KMS_Test_Resources` — you only need valid AWS credentials for the account that owns those
keys. From the TestServer root (`esdk/test-server`):

```bash
# 1. Obtain developer AWS credentials for the account that owns the default
#    KMS_Test_Resources so that `aws sts get-caller-identity` succeeds
#    (Amazon: run `creds`).
creds   # or your environment's equivalent (ada / aws sso login)

# 2. Run the full suite — the KMS scenarios run against the default ARNs.
make test
```

If the shared keys have not been provisioned yet (fresh account), deploy them once with
`make deploy-kms-cdk` and note the printed `CfnOutput`s. To target a **different** set of
keys (e.g. a stack deployed into another account), override the ARNs and run `make test-kms`:

```bash
export DBESDK_TESTSERVER_KMS_SYMMETRIC_KEY_ARN=<symmetricKeyArn>
export DBESDK_TESTSERVER_KMS_MRK_ARN=<mrkArn>
export DBESDK_TESTSERVER_KMS_RSA_KEY_ARN=<rsaKeyArn>
export DBESDK_TESTSERVER_KMS_REGION=us-west-2   # optional
make test-kms
```

Or directly from this `tests/` directory (after `creds`), passing the values as system
properties:

```bash
JAVA_HOME=<jdk21+> ./gradlew test \
  -Desdk.testserver.kms.symmetricKeyArn=<symmetricKeyArn> \
  -Desdk.testserver.kms.mrkArn=<mrkArn> \
  -Desdk.testserver.kms.rsaKeyArn=<rsaKeyArn> \
  -Desdk.testserver.kms.region=us-west-2
```

When configured, you will see additional named executions such as `blob[awsKms]`,
`stream[awsKmsMrk]`, `blob[awsKmsMultiKeyring]`, `blob[awsKmsMrkMultiKeyring]`,
`blob[awsKmsRsa]`, `stream[awsKmsRsa]`, and
`blob[awsKmsDiscovery]` / `stream[awsKmsDiscovery]` alongside the offline scenarios, each
asserting `decrypt(encrypt(x)) == x` byte-for-byte against real AWS KMS. Without credentials
or ARNs, none of these appear and only the offline scenarios run.

## Structural smoke checks (Task 5.4)

```bash
bash smoke/round_trip_smoke_check.sh
```

Verifies exactly one `Tests` definition (no per-language duplicates), the blob round-trip
Test exists, and no stream round-trip Test exists for the first pass (Requirements 4.8, 4.9,
7.1).

## Scope notes

- The standalone `runServer` launcher is intentionally minimal. The full orchestrator
  (`Configuration_Set`, source resolution, multi-language launch, fail-open reporting) is a
  later task and is **not** part of this module.
- The stream round-trip Test is out of scope for the first pass (Requirement 4.9); the stream
  operations/handlers themselves are implemented in the server module.
