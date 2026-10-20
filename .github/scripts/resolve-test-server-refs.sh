#!/usr/bin/env bash
# Resolves the commons ref and the language repository + ref a test-server run
# checks out, and writes them to $GITHUB_OUTPUT as commons_ref,
# language_repository and language_ref.
#
# On a pull request, each line of the description of the form
#   Depends-On: <owner>/<repo>#<number>
#   Depends-On: https://github.com/<owner>/<repo>/pull/<number>
# runs against that pull request's head commit instead of the configured ref.
# Explicit workflow inputs win over Depends-On lines.
#
# Environment:
#   REPOSITORY, SHA               github.repository, github.sha
#   PR_NUMBER, EVENT_BODY         the pull request's number and description, if any
#   INPUT_COMMONS_REF, INPUT_LANGUAGE_REPOSITORY, INPUT_LANGUAGE_REF
#   GH_TOKEN                      reads this repository's pull request
#   REPO_PAT                      reads the private repositories' refs
set -euo pipefail

COMMONS=aws/aws-crypto-tools-commons

# The description is fetched fresh because a re-run replays the original
# event, which carries the description as it was when the run was triggered.
body=""
if [ -n "${PR_NUMBER:-}" ]; then
  if ! body=$(gh api "repos/$REPOSITORY/pulls/$PR_NUMBER" --jq '.body // ""' 2>/dev/null); then
    echo "Could not fetch the description of #$PR_NUMBER; using the triggering event's copy."
    body=${EVENT_BODY:-}
  fi
fi

dep_commons=""
dep_repo=""
dep_ref=""
while IFS= read -r line; do
  line=${line%$'\r'}
  [[ $line =~ ^[[:space:]]*[Dd]epends-[Oo]n:[[:space:]]*(https://github\.com/)?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(#|/pull/)([0-9]+)[[:space:]]*$ ]] || continue
  repo=${BASH_REMATCH[2]}
  number=${BASH_REMATCH[4]}
  sha=$(cd "${RUNNER_TEMP:-/tmp}" && git ls-remote "https://x-access-token:${REPO_PAT}@github.com/$repo.git" "refs/pull/$number/head" | cut -f1)
  if [ -z "$sha" ]; then
    echo "::error::Depends-On: $repo#$number has no head commit, or the token cannot read $repo."
    exit 1
  fi
  echo "Depends-On: $repo#$number -> $sha"
  if [ "$repo" = "$COMMONS" ]; then
    dep_commons=$sha
  elif [ "$REPOSITORY" != "$COMMONS" ]; then
    echo "::error::Depends-On: $repo#$number: a language repository's run can only depend on $COMMONS."
    exit 1
  elif [ -n "$dep_repo" ]; then
    echo "::error::Depends-On: a run can depend on only one language repository ($dep_repo and $repo)."
    exit 1
  else
    dep_repo=$repo
    dep_ref=$sha
  fi
done <<< "$body"

if [ "$REPOSITORY" = "$COMMONS" ]; then
  commons_ref=$SHA
else
  commons_ref=${dep_commons:-${INPUT_COMMONS_REF:-main}}
fi

language_repository=${INPUT_LANGUAGE_REPOSITORY:-$dep_repo}
if [ -z "$language_repository" ] && [ "$REPOSITORY" != "$COMMONS" ]; then
  language_repository=$REPOSITORY
fi

language_ref=${INPUT_LANGUAGE_REF:-}
if [ -z "$language_ref" ]; then
  if [ -n "$dep_repo" ] && [ "$language_repository" = "$dep_repo" ]; then
    language_ref=$dep_ref
  elif [ "$language_repository" = "$REPOSITORY" ]; then
    language_ref=$SHA
  fi
fi

{
  echo "commons_ref=$commons_ref"
  echo "language_repository=$language_repository"
  echo "language_ref=$language_ref"
} | tee -a "${GITHUB_OUTPUT:-/dev/null}"
