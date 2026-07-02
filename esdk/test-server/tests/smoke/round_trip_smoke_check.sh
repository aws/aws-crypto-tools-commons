#!/usr/bin/env bash
# Smoke checks for the single Tests definition and round-trip coverage
# (Task 5.4, Requirements 4.8, 4.9, 7.1).
#
# These are one-time structural facts, verified by direct inspection rather than
# property tests (see the design's Testing Strategy):
#   - exactly one `Tests` definition exists under the ESDK TestServer directory,
#     with zero per-language duplicate copies (Req 7.1)
#   - the blob round-trip Test exists (Req 4.8)
#   - no stream round-trip Test exists for the first pass (Req 4.9)
#
# Exit code 0 means all checks passed; non-zero means a check failed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_SERVER_DIR="$(cd "$TESTS_DIR/.." && pwd)"
SRC_DIR="$TESTS_DIR/src/test/java"

failures=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

# --- Req 7.1: exactly one Tests definition, no per-language duplicates --------
# The Tests live in exactly one module directory (`tests`) directly under the
# ESDK TestServer directory; there must be no sibling per-language test module
# such as `tests-java`, `tests-python`, `java-tests`, etc.
tests_modules="$(find "$TEST_SERVER_DIR" -maxdepth 1 -type d \
    \( -name 'tests' -o -name 'tests-*' -o -name '*-tests' \) | sort)"
tests_module_count="$(printf '%s\n' "$tests_modules" | grep -c . || true)"
if [[ "$tests_module_count" == "1" && "$(basename "$tests_modules")" == "tests" ]]; then
    pass "exactly one Tests module exists and it is 'tests' (Req 7.1)"
else
    fail "expected only the 'tests' module; found: ${tests_modules:-<none>} (Req 7.1)"
fi

# There must be exactly one round-trip Test body definition (BlobRoundTrip.run),
# i.e. the round trip is defined once and not duplicated per language.
roundtrip_defs="$(grep -rlE 'class[[:space:]]+BlobRoundTrip\b' "$SRC_DIR" 2>/dev/null | sort || true)"
roundtrip_def_count="$(printf '%s\n' "$roundtrip_defs" | grep -c . || true)"
if [[ "$roundtrip_def_count" == "1" ]]; then
    pass "exactly one blob round-trip definition (no per-language duplicates) (Req 7.1)"
else
    fail "expected exactly 1 BlobRoundTrip definition, found $roundtrip_def_count (Req 7.1)"
fi

# --- Req 4.8: the blob round-trip Test exists ---------------------------------
if [[ -f "$SRC_DIR/aws/cryptography/esdk/testserver/tests/BlobRoundTripTest.java" ]] \
    && [[ -f "$SRC_DIR/aws/cryptography/esdk/testserver/tests/BlobRoundTripPropertyTest.java" ]]; then
    pass "blob round-trip Tests exist (example + property) (Req 4.8)"
else
    fail "blob round-trip Test file(s) missing (Req 4.8)"
fi

# The round-trip must actually exercise both Encrypt and Decrypt (blob variant).
if grep -q '\.encrypt(' "$SRC_DIR/aws/cryptography/esdk/testserver/tests/BlobRoundTrip.java" \
    && grep -q '\.decrypt(' "$SRC_DIR/aws/cryptography/esdk/testserver/tests/BlobRoundTrip.java"; then
    pass "blob round-trip drives both Encrypt and Decrypt (blob variant) (Req 4.8)"
else
    fail "blob round-trip does not drive both Encrypt and Decrypt (Req 4.8)"
fi

# --- Req 4.9: no stream round-trip Test for the first pass --------------------
# No test source may invoke the stream variants (encryptStream/decryptStream).
stream_calls="$(grep -rlE '\.(encryptStream|decryptStream)\(' "$SRC_DIR" 2>/dev/null | sort || true)"
stream_call_count="$(printf '%s\n' "$stream_calls" | grep -c . || true)"
if [[ "$stream_call_count" == "0" ]]; then
    pass "no stream round-trip Test exists for the first pass (Req 4.9)"
else
    fail "found stream-variant usage in Tests (Req 4.9): ${stream_calls}"
fi

# --- Summary ------------------------------------------------------------------
echo "----------------------------------------"
if [[ "$failures" == "0" ]]; then
    echo "ALL ROUND-TRIP SMOKE CHECKS PASSED"
    exit 0
else
    echo "$failures ROUND-TRIP SMOKE CHECK(S) FAILED" >&2
    exit 1
fi
