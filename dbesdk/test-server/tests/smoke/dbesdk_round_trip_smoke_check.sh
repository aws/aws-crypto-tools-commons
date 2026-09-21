#!/usr/bin/env bash
# ============================================================================
# DB-ESDK TestServer end-to-end smoke check.
# ----------------------------------------------------------------------------
# Starts the DB-ESDK Java Language_Server (test-server/java-v3-server, hosted in
# the aws-database-encryption-sdk-dynamodb product repo) on the configured port,
# waits for it to bind, then runs the credential-free raw-AES item round-trip
# test (ItemEncryptionInteropRoundTripTests.rawAesRoundTrip) from the commons
# `tests/` module against it. Tears the server down whether the test passes or
# fails.
#
# Prerequisites:
#   - JAVA_HOME points at a JDK 21+
#   - The aws-database-encryption-sdk-dynamodb checkout is reachable; by default
#     at <checkouts>/dbesdk/aws-database-encryption-sdk-dynamodb. Override with
#     DBESDK_DBE_REPO=<abs path>.
# ============================================================================
set -eu -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
COMMONS_ROOT="$(cd -- "$TESTS_DIR/../../.." && pwd)"
MODEL_DIR="$(cd -- "$TESTS_DIR/../model" && pwd)"

# Locate the DB-ESDK product repo that hosts the language servers; default to the
# sibling layout <checkouts>/dbesdk/aws-database-encryption-sdk-dynamodb.
DBESDK_DBE_REPO="${DBESDK_DBE_REPO:-$(cd -- "$COMMONS_ROOT/../dbesdk/aws-database-encryption-sdk-dynamodb" 2>/dev/null && pwd || echo "")}"
if [[ -z "$DBESDK_DBE_REPO" || ! -d "$DBESDK_DBE_REPO/test-server/java-v3-server" ]]; then
    echo "ERROR: DBESDK_DBE_REPO not found." >&2
    echo "       Expected an aws-database-encryption-sdk-dynamodb checkout with" >&2
    echo "       test-server/java-v3-server, at" >&2
    echo "       $COMMONS_ROOT/../dbesdk/aws-database-encryption-sdk-dynamodb" >&2
    echo "       or via DBESDK_DBE_REPO=<path>." >&2
    exit 1
fi
SERVER_DIR="$DBESDK_DBE_REPO/test-server/java-v3-server"

PORT="${DBESDK_TESTSERVER_PORT:-8101}"
ENDPOINT="http://127.0.0.1:$PORT"

if [[ -z "${JAVA_HOME:-}" ]]; then
    for cand in /usr/lib/jvm/java-21-amazon-corretto /usr/lib/jvm/java-21 /usr/lib/jvm/java-21-openjdk; do
        if [[ -x "$cand/bin/java" ]]; then
            export JAVA_HOME="$cand"
            break
        fi
    done
fi
if [[ -z "${JAVA_HOME:-}" ]]; then
    echo "ERROR: JAVA_HOME is unset and no JDK 21 could be located." >&2
    exit 1
fi
echo "==> JAVA_HOME=$JAVA_HOME"
echo "==> Commons root:   $COMMONS_ROOT"
echo "==> DB-ESDK server: $SERVER_DIR"
echo "==> Model:          $MODEL_DIR"
echo "==> Endpoint:       $ENDPOINT"

SERVER_LOG="$(mktemp -t dbesdk-smoke-server.XXXXXX.log)"
SERVER_PID=""

cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        # kill the whole process tree started by the gradle wrapper so the
        # actual ServerBootstrap child dies with it.
        pkill -P "$SERVER_PID" 2>/dev/null || true
        kill "$SERVER_PID" 2>/dev/null || true
        sleep 2
        pkill -f "ServerBootstrap $PORT" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "==> Starting Java Language_Server on port $PORT ..."
(
    cd "$SERVER_DIR"
    ./gradlew runServer --args="$PORT" -PmodelDir="$MODEL_DIR" --console=plain
) > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Wait for the server to bind. `runServer` prints "listening at" once ready.
DEADLINE=$(( $(date +%s) + 120 ))
until grep -q "listening at" "$SERVER_LOG" 2>/dev/null; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "ERROR: server process exited before binding." >&2
        tail -n 40 "$SERVER_LOG" >&2
        exit 1
    fi
    if (( $(date +%s) > DEADLINE )); then
        echo "ERROR: server did not report 'listening at' within 120s." >&2
        tail -n 40 "$SERVER_LOG" >&2
        exit 1
    fi
    sleep 1
done
echo "==> Server is up ($SERVER_LOG)"

echo "==> Running ItemEncryptionInteropRoundTripTests.rawAesRoundTrip against $ENDPOINT"
(
    cd "$TESTS_DIR"
    ./gradlew test \
        --tests "aws.cryptography.dbesdk.testserver.tests.item.ItemEncryptionInteropRoundTripTests.rawAesRoundTrip" \
        --console=plain \
        --rerun-tasks \
        -Dtestserver.targets="java:3=$ENDPOINT"
)

echo "==> DB-ESDK TestServer smoke check PASSED"
