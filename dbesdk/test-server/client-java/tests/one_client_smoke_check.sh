#!/usr/bin/env bash
# Smoke check: the TestServer generates exactly one client, and it is Java
# (Task 2.2, Requirement 1.6).
#
# These are one-time structural facts, verified by direct inspection rather than
# property tests (see the design's Testing Strategy):
#   - smithy-build.json declares exactly one java-codegen plugin in "client" mode
#   - that is the only codegen plugin configured (no per-language client)
#   - after a build, exactly one generated typed client class exists
#   - no sibling per-language client module exists (client-java is the only one)
#
# Run a build first (`./gradlew build`) so the generated-client assertion has
# artifacts to inspect; if no build output is present that assertion is skipped
# with a notice rather than failing.
#
# Exit code 0 means all checks passed; non-zero means a check failed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_SERVER_DIR="$(cd "$CLIENT_DIR/.." && pwd)"
BUILD_CONFIG="$CLIENT_DIR/smithy-build.json"

failures=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

# --- Requirement 1.6: exactly one codegen plugin, java-codegen in client mode -
if [[ ! -f "$BUILD_CONFIG" ]]; then
    fail "smithy-build.json missing: $BUILD_CONFIG"
    echo "Aborting remaining checks." >&2
    exit 1
fi

# Count configured build plugins (keys under "plugins").
plugin_count="$(grep -cE '"[a-z0-9-]+-codegen"[[:space:]]*:' "$BUILD_CONFIG" || true)"
if [[ "$plugin_count" == "1" ]]; then
    pass "exactly one codegen plugin is configured (Req 1.6)"
else
    fail "expected exactly 1 codegen plugin, found $plugin_count (Req 1.6)"
fi

if grep -qE '"java-codegen"[[:space:]]*:' "$BUILD_CONFIG"; then
    pass "the single codegen plugin is java-codegen (Java client) (Req 1.6)"
else
    fail "java-codegen plugin not configured (Req 1.6)"
fi

# The generated artifact must be a client (modes includes "client").
if grep -qE '"client"' "$BUILD_CONFIG"; then
    pass "codegen mode is client (Req 1.6)"
else
    fail "codegen is not in client mode (Req 1.6)"
fi

# --- Requirement 1.6: no per-language client module exists -------------------
# The only client module under the TestServer directory is client-java.
client_modules="$(find "$TEST_SERVER_DIR" -maxdepth 1 -type d -name 'client-*' \
    | sort)"
client_module_count="$(printf '%s\n' "$client_modules" | grep -c . || true)"
if [[ "$client_module_count" == "1" && "$(basename "$client_modules")" == "client-java" ]]; then
    pass "exactly one client module exists and it is client-java (Req 1.6)"
else
    fail "expected only client-java; found: ${client_modules:-<none>} (Req 1.6)"
fi

# --- Requirement 1.6: exactly one generated typed client class ---------------
GEN_ROOT="$CLIENT_DIR/build/smithyprojections/dbesdk-test-server-client-java/source/java-codegen/java"
if [[ -d "$GEN_ROOT" ]]; then
    # The interface client class (not the *Impl, and not operation shapes under
    # the generated model/ package) is the single typed client.
    client_classes="$(find "$GEN_ROOT" -name '*Client.java' ! -name '*ClientImpl.java' \
        ! -path '*/model/*' | sort)"
    client_class_count="$(printf '%s\n' "$client_classes" | grep -c . || true)"
    if [[ "$client_class_count" == "1" ]]; then
        pass "exactly one generated typed client class: $(basename "$client_classes") (Req 1.6)"
    else
        fail "expected exactly 1 generated client class, found $client_class_count (Req 1.6)"
    fi
    # Both modeled errors must be generated for the client to unmarshal them.
    for err in GenericServerError DBESDKClientError; do
        if find "$GEN_ROOT" -name "${err}.java" | grep -q .; then
            pass "generated client can unmarshal modeled error ${err} (Req 1.6)"
        else
            fail "generated client missing modeled error ${err} (Req 1.6)"
        fi
    done
else
    echo "NOTICE: no build output at $GEN_ROOT; run './gradlew build' first to" \
         "verify generated-client assertions. Skipping those checks."
fi

# --- Summary -----------------------------------------------------------------
echo "----------------------------------------"
if [[ "$failures" == "0" ]]; then
    echo "ALL ONE-CLIENT SMOKE CHECKS PASSED"
    exit 0
else
    echo "$failures ONE-CLIENT SMOKE CHECK(S) FAILED" >&2
    exit 1
fi
