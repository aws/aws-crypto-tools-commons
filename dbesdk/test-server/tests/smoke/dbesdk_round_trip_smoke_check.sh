#!/usr/bin/env bash
# ============================================================================
# DB-ESDK TestServer end-to-end smoke check.
# ----------------------------------------------------------------------------
# Starts the DB-ESDK Java Language_Server on the configured port, waits for it
# to bind, then runs the JUnit round-trip test (DbeRoundTripTests) in the
# commons `tests/` module against it. Tears the server down whether the test
# passes or fails.
#
# Prerequisites:
#   - JAVA_HOME points at a JDK 21+
#   - The aws-crypto-tools-java repo checkout sits alongside this repo, i.e.:
#         <checkouts>/aws-crypto-tools-commons/          (this repo)
#         <checkouts>/aws-crypto-tools-java/             (server repo)
#     Override the server-repo location with DBESDK_JAVA_REPO=<abs path>.
# ============================================================================
set -eu -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
COMMONS_ROOT="$(cd -- "$TESTS_DIR/../../.." && pwd)"
MODEL_DIR="$(cd -- "$TESTS_DIR/../model" && pwd)"

# Locate the Java Language_Server repo: default to a sibling of the commons
# checkout, honoring an explicit override.
DBESDK_JAVA_REPO="${DBESDK_JAVA_REPO:-$(cd -- "$COMMONS_ROOT/../aws-crypto-tools-java" 2>/dev/null && pwd || echo "")}"
if [[ -z "$DBESDK_JAVA_REPO" || ! -d "$DBESDK_JAVA_REPO/dbesdk/test-server/server" ]]; then
    echo "ERROR: DBESDK_JAVA_REPO not found." >&2
    echo "       Expected the aws-crypto-tools-java checkout at a sibling of the commons" >&2
    echo "       checkout ($COMMONS_ROOT/../aws-crypto-tools-java) or via DBESDK_JAVA_REPO=<path>." >&2
    exit 1
fi
SERVER_DIR="$DBESDK_JAVA_REPO/dbesdk/test-server/server"

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
echo "==> Commons root: $COMMONS_ROOT"
echo "==> Java server:  $SERVER_DIR"
echo "==> Model:        $MODEL_DIR"
echo "==> Endpoint:     $ENDPOINT"

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

echo "==> Running DbeRoundTripTests against $ENDPOINT"
(
    cd "$TESTS_DIR"
    ./gradlew test \
        --tests "aws.cryptography.dbesdk.testserver.tests.DbeRoundTripTests.rawAesRoundTrip" \
        --console=plain \
        --rerun-tasks \
        -Ddbesdk.testserver.endpoint="$ENDPOINT"
)

echo "==> DB-ESDK TestServer smoke check PASSED"
