#!/usr/bin/env bash
# Structural smoke checks for the single Smithy model (Task 1.2).
#
# These are one-time structural facts, verified by direct inspection rather than
# property tests (see the design's Testing Strategy):
#   - exactly one .smithy model file is the contract              (Requirement 1.1)
#   - the transport protocol is declared exactly once              (Requirement 1.4)
#   - all four encrypt/decrypt variant operations are present      (Requirement 4.1)
#   - exactly two modeled error shapes exist                       (Requirement 5.1)
#   - both errors are declared on every operation                  (Requirement 5.4)
#
# Exit code 0 means all checks passed; non-zero means a check failed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODEL_FILE="$MODEL_DIR/esdk-test-server.smithy"

failures=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

# --- Requirement 1.1: exactly one .smithy model file is the contract ---------
smithy_count="$(find "$MODEL_DIR" -maxdepth 1 -name '*.smithy' | wc -l | tr -d ' ')"
if [[ "$smithy_count" == "1" ]]; then
    pass "exactly one .smithy model file is the contract (Req 1.1)"
else
    fail "expected exactly 1 .smithy model file, found $smithy_count (Req 1.1)"
fi

if [[ ! -f "$MODEL_FILE" ]]; then
    fail "model file missing: $MODEL_FILE"
    echo "Aborting remaining checks." >&2
    exit 1
fi

# --- Requirement 1.4: protocol declared exactly once at the service ----------
use_count="$(grep -cE '^use smithy\.protocols#rpcv2Cbor$' "$MODEL_FILE" || true)"
applied_count="$(grep -cE '^@rpcv2Cbor$' "$MODEL_FILE" || true)"
if [[ "$use_count" == "1" && "$applied_count" == "1" ]]; then
    pass "transport protocol declared exactly once at the service (Req 1.4)"
else
    fail "protocol must be imported once and applied once; import=$use_count applied=$applied_count (Req 1.4)"
fi

service_count="$(grep -cE '^service [A-Za-z0-9_]+ \{' "$MODEL_FILE" || true)"
if [[ "$service_count" == "1" ]]; then
    pass "exactly one service is declared (Req 1.1, 1.4)"
else
    fail "expected exactly 1 service, found $service_count"
fi

# --- Requirement 4.1: all four blob/stream variant operations present --------
for op in Encrypt EncryptStream Decrypt DecryptStream; do
    if grep -qE "^operation ${op} \{" "$MODEL_FILE"; then
        pass "operation ${op} is present (Req 4.1)"
    else
        fail "operation ${op} is missing (Req 4.1)"
    fi
done

# CreateClient must also be present (Requirement 3.1).
if grep -qE '^operation CreateClient \{' "$MODEL_FILE"; then
    pass "operation CreateClient is present (Req 3.1)"
else
    fail "operation CreateClient is missing (Req 3.1)"
fi

# --- Requirement 5.1: exactly two modeled error shapes -----------------------
error_shapes="$(grep -B1 -E '^structure [A-Za-z0-9_]+ \{' "$MODEL_FILE" \
    | grep -cE '^@error\(' || true)"
if [[ "$error_shapes" == "2" ]]; then
    pass "exactly two modeled error shapes are defined (Req 5.1)"
else
    fail "expected exactly 2 @error structures, found $error_shapes (Req 5.1)"
fi

for err in GenericServerError ESDKClientError; do
    if grep -qE "^structure ${err} \{" "$MODEL_FILE"; then
        pass "error shape ${err} is defined (Req 5.1)"
    else
        fail "error shape ${err} is missing (Req 5.1)"
    fi
done

# --- Requirement 5.4: both errors declared on every operation ----------------
# Count operation blocks and, within each, confirm both error shapes appear.
op_total="$(grep -cE '^operation [A-Za-z0-9_]+ \{' "$MODEL_FILE" || true)"
# An operation's `errors: [...]` lists each shape on its own line; count blocks
# that contain both GenericServerError and ESDKClientError.
both_errors="$(awk '
    /^operation [A-Za-z0-9_]+ \{/ { inop=1; g=0; e=0 }
    inop && /GenericServerError/ { g=1 }
    inop && /ESDKClientError/    { e=1 }
    inop && /^\}/ { if (g && e) c++; inop=0 }
    END { print c+0 }
' "$MODEL_FILE")"
if [[ "$op_total" == "$both_errors" && "$op_total" != "0" ]]; then
    pass "both modeled errors declared on every operation ($op_total/$op_total) (Req 5.4)"
else
    fail "expected both errors on all $op_total operations, only $both_errors qualify (Req 5.4)"
fi

# --- Summary -----------------------------------------------------------------
echo "----------------------------------------"
if [[ "$failures" == "0" ]]; then
    echo "ALL STRUCTURAL SMOKE CHECKS PASSED"
    exit 0
else
    echo "$failures STRUCTURAL SMOKE CHECK(S) FAILED" >&2
    exit 1
fi
