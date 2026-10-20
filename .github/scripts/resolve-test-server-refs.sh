#!/usr/bin/env bash
# Resolves the refs a test-server run checks out, including any Depends-On
# lines in the pull request description.
#
#   Depends-On: <owner>/<repo>#<number>
#   Depends-On: https://github.com/<owner>/<repo>/pull/<number>
#
# A commons pull request may name any number of language-repository pull
# requests; a language-repository pull request may name a commons pull
# request. Explicit workflow inputs win over Depends-On lines.
#
# Usage:
#   resolve-test-server-refs.sh resolve
#     Writes commons_ref, language_repository, language_ref and
#     language_branches ("<owner>/<repo> <branch>" lines) to $GITHUB_OUTPUT.
#     Environment:
#       REPOSITORY, SHA        github.repository, github.sha
#       PR_NUMBER, EVENT_BODY  the pull request's number and description, if any
#       INPUT_COMMONS_REF, INPUT_LANGUAGE_REPOSITORY, INPUT_LANGUAGE_REF
#       GH_TOKEN               reads this repository's pull request
#       REPO_PAT               reads the private repositories' refs
#   resolve-test-server-refs.sh apply
#     Points every server-config.json entry of each repository in
#     LANGUAGE_BRANCHES at its branch. Run from the commons checkout.
set -euo pipefail

COMMONS=aws/aws-crypto-tools-commons

resolve() {
  # The description is fetched fresh because a re-run replays the original
  # event, which carries the description as it was when the run was triggered.
  local body=""
  if [ -n "${PR_NUMBER:-}" ]; then
    if ! body=$(gh api "repos/$REPOSITORY/pulls/$PR_NUMBER" --jq '.body // ""' 2>/dev/null); then
      echo "Could not fetch the description of #$PR_NUMBER; using the triggering event's copy."
      body=${EVENT_BODY:-}
    fi
  fi

  local dep_commons="" branches="" line repo number remote sha heads branch
  while IFS= read -r line; do
    line=${line%$'\r'}
    [[ $line =~ ^[[:space:]]*[Dd]epends-[Oo]n:[[:space:]]*(https://github\.com/)?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(#|/pull/)([0-9]+)[[:space:]]*$ ]] || continue
    repo=${BASH_REMATCH[2]}
    number=${BASH_REMATCH[4]}
    remote="https://x-access-token:${REPO_PAT}@github.com/$repo.git"
    sha=$(cd "${RUNNER_TEMP:-/tmp}" && git ls-remote "$remote" "refs/pull/$number/head" | cut -f1)
    if [ -z "$sha" ]; then
      echo "::error::Depends-On: $repo#$number has no head commit, or the token cannot read $repo."
      exit 1
    fi
    if [ "$repo" = "$COMMONS" ]; then
      echo "Depends-On: $repo#$number -> $sha"
      dep_commons=$sha
      continue
    fi
    if [ "$REPOSITORY" != "$COMMONS" ]; then
      echo "::error::Depends-On: $repo#$number: a language repository's run can only depend on $COMMONS."
      exit 1
    fi
    # The servers clone by branch name, so take the branch at the head commit.
    heads=$(cd "${RUNNER_TEMP:-/tmp}" && git ls-remote --heads "$remote")
    branch=$(awk -v s="$sha" '$1 == s { sub("refs/heads/", "", $2); print $2; exit }' <<< "$heads")
    if [ -z "$branch" ]; then
      echo "::error::Depends-On: $repo#$number: no branch in $repo is at its head commit $sha (pull requests from forks are not supported)."
      exit 1
    fi
    echo "Depends-On: $repo#$number -> $branch ($sha)"
    branches+="$repo $branch"$'\n'
  done <<< "$body"

  local commons_ref language_repository language_ref
  if [ "$REPOSITORY" = "$COMMONS" ]; then
    commons_ref=$SHA
  else
    commons_ref=${dep_commons:-${INPUT_COMMONS_REF:-main}}
  fi
  language_repository=${INPUT_LANGUAGE_REPOSITORY:-}
  if [ -z "$language_repository" ] && [ "$REPOSITORY" != "$COMMONS" ]; then
    language_repository=$REPOSITORY
  fi
  language_ref=${INPUT_LANGUAGE_REF:-}
  if [ -z "$language_ref" ] && [ "$language_repository" = "$REPOSITORY" ]; then
    language_ref=$SHA
  fi

  {
    echo "commons_ref=$commons_ref"
    echo "language_repository=$language_repository"
    echo "language_ref=$language_ref"
    echo "language_branches<<EOF"
    printf '%s' "$branches"
    echo "EOF"
  } | tee -a "${GITHUB_OUTPUT:-/dev/null}"
}

apply() {
  [ -n "${LANGUAGE_BRANCHES//[[:space:]]/}" ] || return 0
  python3 - "$LANGUAGE_BRANCHES" */test-server/config/server-config.json <<'PY'
import json, re, sys

branches = dict(line.split() for line in sys.argv[1].splitlines() if line.strip())

def repo_of(url):
    return re.sub(r"^(git@github\.com:|https://github\.com/)|\.git$|/$", "", url)

for path in sys.argv[2:]:
    with open(path) as f:
        config = json.load(f)
    changed = False
    for entry in config.get("entries", []):
        for key, field in (("libraryRepository", "branch"), ("serverLocation", "ref")):
            location = entry.get(key) or {}
            branch = branches.get(repo_of(location.get("url", "")))
            if branch:
                location[field] = branch
                changed = True
                print(f"{path}: {entry['language']} {key}.{field} -> {branch}")
    if changed:
        with open(path, "w") as f:
            json.dump(config, f, indent=2)
            f.write("\n")
PY
}

case "${1:-}" in
  resolve) resolve ;;
  apply) apply ;;
  *) echo "usage: $0 resolve|apply" >&2; exit 2 ;;
esac
