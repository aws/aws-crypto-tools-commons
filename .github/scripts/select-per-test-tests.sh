#!/usr/bin/env bash
# Picks the shared Tests that the per-test coverage pass records.
#
# A push or a nightly run records every Test. A pull request records only the
# Tests whose duvet test annotations it changes, or whose cited code it
# changes; with none, the pass is skipped. The duvet test reach check of a
# pull request reads only those Tests, so nothing it needs is left out.
#
# Writes PER_TEST_RUN (true or false) and PER_TEST_TESTS (a comma-separated
# Gradle --tests filter; empty runs every Test) to $GITHUB_ENV.
#
# Environment:
#   EVENT_NAME, BASE_SHA   github.event_name and the pull request's base commit
#   REPOSITORY             github.repository
#   PRODUCT                esdk, mpl, dbesdk or primitives
#   LANGUAGE_DIR           the language repository's checkout, if there is one
# Run from the commons checkout.
set -euo pipefail

if [ "$EVENT_NAME" != pull_request ]; then
  { echo "PER_TEST_RUN=true"; echo "PER_TEST_TESTS="; } >> "$GITHUB_ENV"
  echo "Not a pull request: recording every Test."
  exit 0
fi

args=(--language any --library "$PRODUCT" --repository "$REPOSITORY" --commons-root .
      --shared-tests "$PRODUCT/test-server/tests/src/test/java"
      --prefix specification/=spec/ --select-tests "$RUNNER_TEMP/per-test-selection.json")
if [ "$REPOSITORY" = aws/aws-crypto-tools-commons ]; then
  changed=.
  args+=(--repo-root . --changed-since "commons=$BASE_SHA")
elif [ ! -e "$LANGUAGE_DIR/.git" ]; then
  # Without the language checkout its diff is unknown, so every Test is recorded.
  echo "::warning::no checkout at $LANGUAGE_DIR: recording every Test."
  { echo "PER_TEST_RUN=true"; echo "PER_TEST_TESTS="; } >> "$GITHUB_ENV"
  exit 0
else
  changed=$LANGUAGE_DIR
  args+=(--repo-root "$LANGUAGE_DIR" --source . --changed-since "library=$BASE_SHA")
fi
# The checkout is shallow; the diff needs the history back to the base.
git -C "$changed" fetch -q --no-tags --unshallow origin || git -C "$changed" fetch -q --no-tags origin "$BASE_SHA"

python3 test-server-common/tools/duvet_test_reach.py "${args[@]}"
tests=$(python3 -c 'import json, sys; print(",".join(json.load(open(sys.argv[1]))["shared"]))' \
  "$RUNNER_TEMP/per-test-selection.json")
if [ -z "$tests" ]; then
  echo "PER_TEST_RUN=false" >> "$GITHUB_ENV"
  echo "This pull request changes no duvet annotation of a shared Test: skipping the per-test pass."
else
  { echo "PER_TEST_RUN=true"; echo "PER_TEST_TESTS=$tests"; } >> "$GITHUB_ENV"
  echo "Recording only: $tests"
fi
