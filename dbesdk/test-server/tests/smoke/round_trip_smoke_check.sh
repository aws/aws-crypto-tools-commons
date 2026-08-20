#!/usr/bin/env bash
# Smoke checks for the single Tests definition and round-trip coverage
# (Task 5.4, Requirements 4.8, 4.9, 7.1).
#
# These are one-time structural facts, verified by direct inspection rather than
# property tests (see the design's Testing Strategy):
#   - exactly one `Tests` definition exists under the ESDK TestServer directory,
#     with zero per-language duplicate copies (Req 7.1)
#   - the single per-configuration class `MaterialsRoundTripTests` exists and holds
#     BOTH a blob (`blob[...]`) and a stream (`stream[...]`) `@ParameterizedTest`
#     over `EsdkClientConfigs.scenarios()` (Req 4.8, 4.9, 4.4)
#   - there is exactly one BlobRoundTrip and one StreamRoundTrip shared body (Req 7.1)
#   - a cross-language stream round-trip Test does not yet exist (Req 4.10)
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
# The per-configuration blob round-trip lives in the single MaterialsRoundTripTests
# class; the arbitrary-plaintext breadth lives in the jqwik Property 1 test.
MATERIALS_TESTS="$SRC_DIR/aws/cryptography/dbesdk/testserver/tests/MaterialsRoundTripTests.java"
if [[ -f "$MATERIALS_TESTS" ]] \
    && [[ -f "$SRC_DIR/aws/cryptography/dbesdk/testserver/tests/BlobRoundTripPropertyTest.java" ]]; then
    pass "blob round-trip Tests exist (MaterialsRoundTripTests + Property 1) (Req 4.8)"
else
    fail "blob round-trip Test file(s) missing (Req 4.8)"
fi

# The round-trip must actually exercise both Encrypt and Decrypt (blob variant).
if grep -q '\.encrypt(' "$SRC_DIR/aws/cryptography/dbesdk/testserver/tests/BlobRoundTrip.java" \
    && grep -q '\.decrypt(' "$SRC_DIR/aws/cryptography/dbesdk/testserver/tests/BlobRoundTrip.java"; then
    pass "blob round-trip drives both Encrypt and Decrypt (blob variant) (Req 4.8)"
else
    fail "blob round-trip does not drive both Encrypt and Decrypt (Req 4.8)"
fi

# --- Per-scenario config coverage: the single MaterialsRoundTripTests class ---
# Per-scenario keyring/CMM/algorithm-suite coverage is guaranteed by the single
# per-configuration class MaterialsRoundTripTests, which holds BOTH a blob and a
# stream round-trip test, each a deterministic JUnit 5 parameterized test (one
# named execution per scenario via @MethodSource over EsdkClientConfigs.scenarios()).
# The jqwik Property 1 / Property 15 tests complement it for arbitrary-plaintext
# breadth but are not the coverage guarantee (design "Per-scenario config coverage
# for the Java hardening pass").
if [[ -f "$MATERIALS_TESTS" ]] \
    && grep -q 'EsdkClientConfigs.scenarios' "$MATERIALS_TESTS"; then
    pass "single per-configuration class MaterialsRoundTripTests exists over EsdkClientConfigs.scenarios() (Req 4.4)"
else
    fail "MaterialsRoundTripTests (per-configuration class over EsdkClientConfigs.scenarios()) missing (Req 4.4)"
fi

# It must contain a blob round-trip parameterized test named blob[...] over the scenarios.
if [[ -f "$MATERIALS_TESTS" ]] \
    && grep -qE '@ParameterizedTest\(name = "blob\[\{0\}\]"\)' "$MATERIALS_TESTS"; then
    pass "MaterialsRoundTripTests contains a blob[...] parameterized round-trip over every scenario (Req 4.4)"
else
    fail "MaterialsRoundTripTests missing the blob[...] parameterized round-trip (Req 4.4)"
fi

# --- Req 4.9: a single-server stream round-trip Test exists -------------------
# The stream round-trip also lives in MaterialsRoundTripTests as a parameterized
# test named stream[...] over every scenario (the stream variants
# encryptStream/decryptStream on the same Streaming_Capable Java server); the
# arbitrary-plaintext breadth lives in the jqwik Property 15 test.
if [[ -f "$MATERIALS_TESTS" ]] \
    && grep -qE '@ParameterizedTest\(name = "stream\[\{0\}\]"\)' "$MATERIALS_TESTS" \
    && [[ -f "$SRC_DIR/aws/cryptography/dbesdk/testserver/tests/StreamRoundTripPropertyTest.java" ]]; then
    pass "single-server stream round-trip Tests exist (MaterialsRoundTripTests stream[...] + Property 15) (Req 4.9)"
else
    fail "single-server stream round-trip Test(s) missing (Req 4.9)"
fi

# There must be exactly one stream round-trip Test body definition
# (StreamRoundTrip.run), i.e. defined once and not duplicated per language.
stream_roundtrip_defs="$(grep -rlE 'class[[:space:]]+StreamRoundTrip\b' "$SRC_DIR" 2>/dev/null | sort || true)"
stream_roundtrip_def_count="$(printf '%s\n' "$stream_roundtrip_defs" | grep -c . || true)"
if [[ "$stream_roundtrip_def_count" == "1" ]]; then
    pass "exactly one stream round-trip definition (no per-language duplicates) (Req 7.1)"
else
    fail "expected exactly 1 StreamRoundTrip definition, found $stream_roundtrip_def_count (Req 7.1)"
fi

# The stream round-trip must actually exercise both stream variants.
if grep -q '\.encryptStream(' "$SRC_DIR/aws/cryptography/dbesdk/testserver/tests/StreamRoundTrip.java" \
    && grep -q '\.decryptStream(' "$SRC_DIR/aws/cryptography/dbesdk/testserver/tests/StreamRoundTrip.java"; then
    pass "stream round-trip drives both EncryptStream and DecryptStream (Req 4.9)"
else
    fail "stream round-trip does not drive both EncryptStream and DecryptStream (Req 4.9)"
fi

# --- Req 4.10: no cross-language stream round-trip Test yet --------------------
# A cross-language stream round-trip (spanning two distinct Streaming_Capable
# languages) is out of scope until at least two Streaming_Capable servers exist.
# No such Test may be present yet.
cross_stream="$(grep -rlE 'CrossLanguage.*Stream|Stream.*CrossLanguage' "$SRC_DIR" 2>/dev/null | sort || true)"
cross_stream_count="$(printf '%s\n' "$cross_stream" | grep -c . || true)"
if [[ "$cross_stream_count" == "0" ]]; then
    pass "no cross-language stream round-trip Test exists yet (Req 4.10)"
else
    fail "found a cross-language stream round-trip Test (Req 4.10): ${cross_stream}"
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
