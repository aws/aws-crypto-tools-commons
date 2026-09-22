#!/usr/bin/env bash
# Model-validation smoke check: the model gate rejects aws.polymorph (Task 1.3).
#
# Asserts two behaviors:
#   1. The real model passes the no-polymorph gate (it contains zero
#      aws.polymorph traits, Requirement 1.2).
#   2. When an aws.polymorph trait is injected into a copy of the model, the
#      gate fails with an error that names the disallowed trait and signals that
#      no Language_Server is generated (Requirement 1.3).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
GATE="$SCRIPT_DIR/validate-no-polymorph.sh"

failures=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

# --- Case 1: the real model passes the gate ----------------------------------
if bash "$GATE" "$MODEL_DIR" >/dev/null 2>&1; then
    pass "real model passes the no-polymorph gate (Req 1.2)"
else
    fail "real model unexpectedly rejected by the no-polymorph gate (Req 1.2)"
fi

# --- Case 2: an injected aws.polymorph trait is rejected ----------------------
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
cp "$MODEL_DIR/dbesdk-test-server.smithy" "$TMP_DIR/tainted.smithy"

# Inject a representative aws.polymorph reference (an import + a trait use).
cat >> "$TMP_DIR/tainted.smithy" <<'EOF'

use aws.polymorph#localService

@localService(sdkId: "DBESDKTestServer", config: ESDKClientConfig)
structure TaintedShape {}
EOF

set +e
gate_output="$(bash "$GATE" "$TMP_DIR" 2>&1)"
gate_exit=$?
set -e

if [[ "$gate_exit" -ne 0 ]]; then
    pass "injected aws.polymorph trait is rejected with non-zero exit (Req 1.3)"
else
    fail "gate accepted a model containing aws.polymorph (Req 1.3)"
fi

if echo "$gate_output" | grep -q 'aws.polymorph'; then
    pass "rejection message names the disallowed trait 'aws.polymorph' (Req 1.3)"
else
    fail "rejection message does not name the disallowed trait (Req 1.3)"
fi

if echo "$gate_output" | grep -qi 'no Language_Server generated\|no server'; then
    pass "rejection signals that no server is generated (Req 1.3)"
else
    fail "rejection does not signal that no server is generated (Req 1.3)"
fi

# --- Summary -----------------------------------------------------------------
echo "----------------------------------------"
if [[ "$failures" == "0" ]]; then
    echo "ALL POLYMORPH-REJECTION CHECKS PASSED"
    exit 0
else
    echo "$failures POLYMORPH-REJECTION CHECK(S) FAILED" >&2
    exit 1
fi
