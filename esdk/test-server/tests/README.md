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

## Option A — Automated (recommended): the test harness boots the server for you

From this `tests/` directory:

```bash
JAVA_HOME=<jdk21+> ./gradlew test
```

With no endpoint configured, the suite boots one Java `Language_Server` in-process on an
ephemeral port (real Netty HTTP + rpcv2Cbor) and uses it as **both** the encrypt and decrypt
endpoint of the pair, then performs the real over-HTTP round trip. This runs:

- `BlobRoundTripTest` — example + empty-plaintext round trips (Task 5.2)
- `BlobRoundTripPropertyTest` — Property 1, jqwik, 100 iterations, arbitrary/empty/binary/large
  plaintext (Task 5.3)

## Option B — Manual two-step: start the Java server, then run the Tests against it

Start the server (Terminal 1), from `../servers/java`:

```bash
# default port 8080
JAVA_HOME=<jdk21+> ./gradlew runServer
# or pick a port (any of the three forms works):
JAVA_HOME=<jdk21+> ./gradlew runServer --args="9090"
JAVA_HOME=<jdk21+> ./gradlew runServer -Pport=9090
```

It prints, e.g.:

```
ESDK TestServer (Java) listening at http://127.0.0.1:9090
Point the Tests at it with: -Desdk.testserver.endpoints=http://127.0.0.1:9090
```

Run the Tests against that endpoint (Terminal 2), from this `tests/` directory:

```bash
JAVA_HOME=<jdk21+> ./gradlew test -Desdk.testserver.endpoints=http://127.0.0.1:9090
```

Stop the server with Ctrl-C when done.

### Runtime endpoint configuration (Requirement 7.3)

The suite reads endpoints, in precedence order, from:

1. system property `esdk.testserver.endpoints`
2. environment variable `ESDK_TESTSERVER_ENDPOINTS`

The value is a comma-separated list of base URLs. The **first** is the encrypt endpoint and
the **second** (if present) is the decrypt endpoint; a single entry is used for both sides of
the round trip. This is how later multi-language pairs are exercised — by changing config
only, e.g. `-Desdk.testserver.endpoints=http://127.0.0.1:9090,http://127.0.0.1:9091`.

The server launcher (`../servers/java runServer`) reads its port from the first CLI arg, the
`-Pport=<n>` Gradle property, the system property `esdk.testserver.port`, or the
`ESDK_TESTSERVER_PORT` env var, defaulting to `8080`.

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
