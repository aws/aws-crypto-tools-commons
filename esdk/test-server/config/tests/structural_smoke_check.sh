#!/usr/bin/env bash
# ============================================================================
# Structural smoke check — aws-crypto-tools-commons factoring (task 15.1)
# ----------------------------------------------------------------------------
# Asserts the shipped factoring of the ESDK TestServer as seen from the
# Commons_Repository. This lives in config/tests/ because the Configuration_Set
# (config/server-config.json + feature-set.json) is the primary subject, following the
# model/tests/*.sh precedent of a tests/ subdir under the owning component
# (esdk/test-server/tests/ is the Tests Gradle module, so it is NOT a home for
# shell checks about the repo).
#
#   * Requirements 1.1, 1.3: the Configuration_Set names the Java
#     Language_Server in the aws-crypto-tools-java Language_Repository
#     (serverLocation.repository "aws-crypto-tools-java", path
#     "esdk/test-server/server") and the Python Language_Server in commons
#     (serverLocation.repository "aws-crypto-tools-commons").
#   * Requirement 1.8: commons contains zero copies of the Java
#     Language_Server — no esdk/test-server/servers/java directory.
#   * Requirement 10.1: exactly one Tests definition exists — exactly one
#     MaterialsRoundTripTests.java in the repository, under
#     esdk/test-server/tests/.
#   * Requirements 7.1, 7.3: product is exactly "esdk" and the
#     Feature_Catalog defines exactly the Features "streaming", "MPL", and
#     "hierarchical".
#   * Requirement 8.13: the Python Configuration_Entry carries the Python
#     Feature_Declaration — supportedFeatures lists both streaming and MPL,
#     unsupportedFeatures lists neither.
#   * Requirement 2.7: the Makefile has no separate cross-language target
#     (no test-cross-language) — `make orchestrate` is the single entry point.
#
# Hermetic: no network, no JDK, no AWS — pure filesystem + python3 JSON
# assertions. Repository-wide scans exclude .git/, Gradle build/.gradle
# scratch, the Python server's .deps/.venv, node_modules, and .make-tmp: they
# are not part of this repository's own factoring.
#
# Usage:  bash config/tests/structural_smoke_check.sh   (or via `make validate`)
# Exit code 0 means all checks passed; non-zero means a check failed.
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"    # aws-crypto-tools-commons/esdk/test-server
REPO_ROOT="$(cd "$TS_DIR/../.." && pwd)"     # aws-crypto-tools-commons
SERVER_CONFIG="$TS_DIR/config/server-config.json"
FEATURE_CONFIG="$TS_DIR/config/feature-set.json"
PYTHON_FEATURE="$TS_DIR/servers/python/feature-config.json"
MAKEFILE="$TS_DIR/Makefile"

failures=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

# Repository-wide scans skip these (not part of this repo's own factoring).
# Usage: repo_find <find-args...> — a find over $REPO_ROOT with the prunes.
repo_find() {
  find "$REPO_ROOT" \
    \( -name .git -o -name build -o -name .gradle -o -name node_modules \
       -o -name .deps -o -name .venv -o -name .make-tmp \) -prune \
    -o "$@" -print 2>/dev/null
}

for f in "$SERVER_CONFIG" "$FEATURE_CONFIG"; do
    if [ ! -f "$f" ]; then
        fail "config file missing: $f"
        echo "Aborting remaining checks." >&2
        exit 1
    fi
done

# ----------------------------------------------------------------------------
# Check 1: Server_Locations — Java server in aws-crypto-tools-java, Python
# server in commons (Req 1.1, 1.3)
# ----------------------------------------------------------------------------
if location_errors=$(python3 - "$SERVER_CONFIG" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
entries = {e.get("language"): e for e in cfg.get("entries", [])}
errors = []

java = entries.get("java")
if not isinstance(java, dict):
    errors.append("no java Configuration_Entry")
else:
    loc = java.get("serverLocation") or {}
    if loc.get("repository") != "aws-crypto-tools-java":
        errors.append('java serverLocation.repository is %r, expected "aws-crypto-tools-java"'
                      % loc.get("repository"))
    if loc.get("path") != "esdk/test-server/server":
        errors.append('java serverLocation.path is %r, expected "esdk/test-server/server"'
                      % loc.get("path"))

python = entries.get("python")
if not isinstance(python, dict):
    errors.append("no python Configuration_Entry")
else:
    loc = python.get("serverLocation") or {}
    if loc.get("repository") != "aws-crypto-tools-commons":
        errors.append('python serverLocation.repository is %r, expected "aws-crypto-tools-commons"'
                      % loc.get("repository"))

print("\n".join(errors))
sys.exit(1 if errors else 0)
PY
); then
    pass "Java server located in aws-crypto-tools-java at esdk/test-server/server; Python server in commons (Req 1.1, 1.3)"
else
    if [ -n "$location_errors" ]; then
        fail "Server_Location violation: ${location_errors//$'\n'/; } (Req 1.1, 1.3)"
    else
        fail "server-config.json is not parseable JSON (Req 1.1, 1.3)"
    fi
fi

# ----------------------------------------------------------------------------
# Check 2: no commons copy of the Java Language_Server (Req 1.8)
# ----------------------------------------------------------------------------
if [ ! -e "$TS_DIR/servers/java" ]; then
    pass "no esdk/test-server/servers/java directory — commons holds zero Java server copies (Req 1.8)"
else
    fail "esdk/test-server/servers/java exists — the Java Language_Server must live only in aws-crypto-tools-java (Req 1.8)"
fi

# ----------------------------------------------------------------------------
# Check 3: exactly one Tests definition, under esdk/test-server/tests/ (Req 10.1)
# ----------------------------------------------------------------------------
tests_copies="$(repo_find -type f -name 'MaterialsRoundTripTests.java')"
tests_count="$(printf '%s' "$tests_copies" | grep -c . || true)"
expected_tests="$TS_DIR/tests/src/test/java/aws/cryptography/esdk/testserver/tests/MaterialsRoundTripTests.java"
if [ "$tests_count" = "1" ] && [ "$tests_copies" = "$expected_tests" ]; then
    pass "exactly one Tests definition, under esdk/test-server/tests/ (Req 10.1)"
else
    fail "expected exactly 1 MaterialsRoundTripTests.java at $expected_tests, found $tests_count: ${tests_copies//$'\n'/, } (Req 10.1)"
fi

# ----------------------------------------------------------------------------
# Check 4: product is "esdk" and the Feature_Catalog is exactly
# ["streaming", "MPL"] (Req 7.1, 7.3)
# ----------------------------------------------------------------------------
if catalog_errors=$(python3 - "$SERVER_CONFIG" "$FEATURE_CONFIG" <<'PY'
import json, sys
server = json.load(open(sys.argv[1]))
feature = json.load(open(sys.argv[2]))
errors = []
if server.get("product") != "esdk":
    errors.append('product is %r, expected exactly "esdk"' % server.get("product"))
features = feature.get("features")
if not isinstance(features, list) or sorted(features) != sorted(["streaming", "MPL", "hierarchical", "raw-aes", "raw-rsa", "raw-ecdh", "multi", "aws-kms", "aws-kms-multi", "aws-kms-discovery", "aws-kms-mrk", "aws-kms-mrk-multi", "aws-kms-mrk-discovery", "aws-kms-rsa", "aws-kms-ecdh", "required-encryption-context", "caching"]):
    errors.append('Feature_Catalog is %r, expected exactly the per-keyring/per-CMM Feature_Catalog' % features)
print("\n".join(errors))
sys.exit(1 if errors else 0)
PY
); then
    pass 'product is "esdk" and the Feature_Catalog defines the per-keyring/per-CMM Features (Req 7.1, 7.3)'
else
    if [ -n "$catalog_errors" ]; then
        fail "product/Feature_Catalog violation: ${catalog_errors//$'\n'/; } (Req 7.1, 7.3)"
    else
        fail "server-config.json / feature-set.json is not parseable JSON (Req 7.1, 7.3)"
    fi
fi

# ----------------------------------------------------------------------------
# Check 5: Python Feature_Declaration supports streaming + MPL (Req 8.13)
# ----------------------------------------------------------------------------
if declaration_errors=$(python3 - "$PYTHON_FEATURE" <<'PY'
import json, sys
python = json.load(open(sys.argv[1]))
supported = python.get("supportedFeatures")
unsupported = python.get("unsupportedFeatures")
errors = []
if not isinstance(supported, list):
    errors.append("python supportedFeatures array is missing")
if not isinstance(unsupported, list):
    errors.append("python unsupportedFeatures array is missing")
if not errors:
    for feature in ("streaming", "MPL"):
        if feature not in supported:
            errors.append('"%s" is not in python supportedFeatures' % feature)
        if feature in unsupported:
            errors.append('"%s" appears in python unsupportedFeatures' % feature)
print("\n".join(errors))
sys.exit(1 if errors else 0)
PY
); then
    pass "python supportedFeatures lists streaming and MPL; unsupportedFeatures lists neither (Req 8.13)"
else
    if [ -n "$declaration_errors" ]; then
        fail "python Feature_Declaration violation: ${declaration_errors//$'\n'/; } (Req 8.13)"
    else
        fail "python feature-config.json is not parseable JSON (Req 8.13)"
    fi
fi

# ----------------------------------------------------------------------------
# Check 6: the Makefile has no separate cross-language target (Req 2.7)
# ----------------------------------------------------------------------------
if [ ! -f "$MAKEFILE" ]; then
    fail "Makefile missing: $MAKEFILE (Req 2.7)"
elif grep -qE '^test-cross-language\s*:' "$MAKEFILE"; then
    fail "Makefile defines a test-cross-language target — 'make orchestrate' must be the single cross-language entry point (Req 2.7)"
else
    pass "Makefile has no test-cross-language target — 'make orchestrate' is the single entry point (Req 2.7)"
fi

# --- Summary -----------------------------------------------------------------
echo "----------------------------------------"
if [ "$failures" = "0" ]; then
    echo "ALL FACTORING SMOKE CHECKS PASSED"
    exit 0
else
    echo "$failures FACTORING SMOKE CHECK(S) FAILED" >&2
    exit 1
fi
