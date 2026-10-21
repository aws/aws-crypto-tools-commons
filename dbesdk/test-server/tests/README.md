# DB-ESDK TestServer — Tests (single suite) and how to run them

This module holds **the single `Tests` definition** (Requirement 7.1). It drives every
`Language_Server` exclusively through the **one** generated Java `Test_Client`
(Requirement 1.6). Which endpoint(s) the Tests target comes from **runtime configuration
only** (Requirement 7.3) — pointing the suite at a different server is a config change with
no change to the Tests.

The Tests exercise the **DB-ESDK item-encryption API** end to end: `CreateClient` on each
endpoint of a pair, then item operations (`EncryptItem` / `DecryptItem`), the DynamoDB
request/response transforms (`PutItem` / `GetItem` / `Query` / `Scan` / `BatchWriteItem` /
`TransactWriteItems` / `UpdateItem` / `DeleteItem` / …), structured encryption
(`EncryptStructure` / `DecryptStructure`), and searchable encryption (beacons). DB-ESDK's
unit of encryption is a bounded DDB item, so there is **no streaming API** and no blob/stream
round-trip.

The first-pass, credential-free Test is the **raw-AES item round-trip**
(`ItemEncryptionInteropRoundTripTests.rawAesRoundTrip`): `CreateClient` on each endpoint,
`EncryptItem` on one, `DecryptItem` on the other, asserting the recovered item is preserved.
It uses a fully offline **Raw-AES** keyring, so there are **no KMS/network calls**.

Everything runs over the **real rpcv2Cbor wire protocol over HTTP**:

```
generated Java Test_Client  ──HTTP (rpcv2Cbor)──▶  DB-ESDK Language_Server  ──▶  real AWS DB-ESDK
```

## Configuration and feature/bug declarations

The commons configuration is the three-file trio in `../config/`:

- `server-config.json` — product identity, one Configuration_Entry per language, optional
  required-KMS scenarios;
- `feature-set.json` — the authoritative Feature_Catalog;
- `bug-list.json` — the authoritative bug ledger, keyed by bug id.

Each language server declares its own trio (`server-config.json` + `feature-config.json` +
`bug-config.json`): a per-catalog-feature supported/unsupported classification and the flat
list of bug ids that server exhibits. A feature a target declares unsupported is skipped for
that target with the reason recorded; a declared known bug is tolerated (skipped) until it
stops reproducing, at which point the run fails so the declaration is removed.

## Prerequisites

- **JDK 21+** is required by smithy-java. Set `JAVA_HOME` to a JDK 21+ install.

## Option A — Orchestrated (recommended): the orchestrator launches the servers

The Tests are **endpoint-only** (Requirement 10.2): they never boot a server themselves.
`make orchestrate` (from the TestServer root) resolves and launches every configured
`Language_Server` as a subprocess, waits for all to become reachable, and runs the Tests with
the `testserver.targets` property set. The cross-language matrix is the full pairwise
(encrypt, decrypt) product of the launched targets, including same-target pairs.

## Option B — Manual two-step: start a Language_Server, then run the Tests against it

Start a server yourself (the Java server via `./gradlew runServer --args="8101"
-PmodelDir=<commons>/dbesdk/test-server/model` in `test-server/java-v3-server` of the
`aws-database-encryption-sdk-dynamodb` repo), then run the Tests from this `tests/` directory,
pointing them at the running endpoint(s):

```bash
JAVA_HOME=<jdk21+> ./gradlew test \
  -Dtestserver.targets=java:3=http://127.0.0.1:8101
```

Stop the server with Ctrl-C when done.

### Runtime target configuration (Requirements 7.3, 10.2)

The suite reads its targets, in precedence order, from:

1. system property `testserver.targets`
2. environment variable `TESTSERVER_TARGETS`

The value is a comma-separated list of `<language>:<majorVersion>=<endpointUrl>` entries,
e.g. `java:3=http://127.0.0.1:8101,net:4=http://127.0.0.1:8103`. **When no targets are
configured the Tests fail with an actionable message** — there is no managed (in-process)
fallback.

## Online AWS KMS scenarios (credential-gated)

The KMS-backed keyring scenarios (`AwsKms`, `AwsKmsMrk`, `AwsKmsRsa`, `AwsKmsHierarchical`,
…) make real AWS KMS calls, so they require **AWS credentials** and network access. The key
ARNs and region are read from system properties (or the matching environment variables),
falling back to the shared CI test keys:

| System property | Environment variable |
|---|---|
| `dbesdk.testserver.kms.symmetricKeyArn` | `DBESDK_TESTSERVER_KMS_SYMMETRIC_KEY_ARN` |
| `dbesdk.testserver.kms.mrkArn` | `DBESDK_TESTSERVER_KMS_MRK_ARN` |
| `dbesdk.testserver.kms.rsaKeyArn` | `DBESDK_TESTSERVER_KMS_RSA_KEY_ARN` |
| `dbesdk.testserver.kms.region` | `DBESDK_TESTSERVER_KMS_REGION` (default `us-west-2`) |

Without usable credentials the KMS scenarios fail; the offline Raw-AES scenarios and the
credential-free property tests run regardless.

## Smoke checks

```bash
make smoke          # model structural + reject-polymorph checks, then the round-trip smoke
make smoke-dbesdk   # just launch the DB-ESDK Java server + run the raw-AES item round-trip
```

`smoke/dbesdk_round_trip_smoke_check.sh` launches `test-server/java-v3-server` from the
`aws-database-encryption-sdk-dynamodb` repo (override its location with `DBESDK_DBE_REPO`)
and runs `ItemEncryptionInteropRoundTripTests.rawAesRoundTrip` against it via
`-Dtestserver.targets=java:3=<endpoint>`.

## Scope notes

- The per-language Language_Servers live in the `aws-database-encryption-sdk-dynamodb`
  product repo under `test-server/<lang>-v<major>-server/`; the shared model, generated Java
  Test_Client, common Tests, orchestrator, and test-support stay in commons.
- DB-ESDK item encryption has no streaming API, so there are no stream round-trip Tests.
