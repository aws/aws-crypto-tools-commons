#!/usr/bin/env bash
# Reusable model-validation gate (Requirements 1.2, 1.3).
#
# The Smithy_Model must use only plain Smithy 2.0 constructs and contain zero
# `aws.polymorph` traits. This script scans every .smithy file under a model
# directory; if any `aws.polymorph` trait (or namespace import) is present it
# rejects the model with a non-zero exit code, prints an error naming the
# disallowed trait, and emits an explicit "no server generated" signal so that
# downstream codegen is never invoked on a rejected model.
#
# Usage: validate-no-polymorph.sh <model-dir>
set -euo pipefail

MODEL_DIR="${1:?usage: validate-no-polymorph.sh <model-dir>}"

if [[ ! -d "$MODEL_DIR" ]]; then
    echo "ERROR: model directory not found: $MODEL_DIR" >&2
    exit 2
fi

# Strip `//` line comments before scanning so that prose mentioning the trait
# name does not produce false positives; a real reference always uses the
# `aws.polymorph#<shape>` namespace syntax (an import or a qualified trait).
matches="$(grep -rl --include='*.smithy' '.' "$MODEL_DIR" 2>/dev/null | while read -r f; do
    sed 's://.*$::' "$f" | grep -nE 'aws\.polymorph#' | sed "s|^|$f:|" || true
done)"

if [[ -n "$matches" ]]; then
    echo "ERROR: disallowed trait namespace 'aws.polymorph' found in the Smithy model." >&2
    echo "       The model must use only plain Smithy 2.0 constructs (Requirement 1.2)." >&2
    echo "$matches" >&2
    echo "RESULT: model rejected; no Language_Server generated (Requirement 1.3)." >&2
    exit 1
fi

echo "OK: no aws.polymorph traits present in $MODEL_DIR"
exit 0
