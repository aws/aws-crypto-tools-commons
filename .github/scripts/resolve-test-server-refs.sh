#!/usr/bin/env bash
# Resolves the refs a test-server run checks out, including any
# Test-Server-Override lines in the pull request description.
#
#   ```
#   Test-Server-Override: <owner>/<repo>#<number>, https://github.com/<owner>/<repo>/pull/<number>
#   ```
#
# Only lines in the description's last code block count, so examples earlier
# in the description are ignored. A line takes a comma-separated list, and the
# block may have several lines.
#
# Each line runs that pull request's head in place of the repository's
# configured branch, for this run only. A pull request may name any number of
# repositories. Its own repository always runs from its checkout. Explicit
# workflow inputs win over override lines.
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

  local dep_commons="" branches="" line repo number remote sha heads branch items
  # The lines of the last fenced code block.
  body=$(awk '/^[[:space:]]*```/ { if (fenced) { last = block; fenced = 0 } else { block = ""; fenced = 1 } next }
              fenced { block = block $0 "\n" }
              END { printf "%s", last }' <<< "$body")

  local refs=() item
  while IFS= read -r line; do
    line=${line%$'\r'}
    [[ $line =~ ^[[:space:]]*[Tt]est-[Ss]erver-[Oo]verride:(.*)$ ]] || continue
    IFS=, read -ra items <<< "${BASH_REMATCH[1]}"
    for item in "${items[@]}"; do
      item=$(xargs <<< "$item")
      [ -n "$item" ] || continue
      if ! [[ $item =~ ^(https://github\.com/)?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(#|/pull/)([0-9]+)$ ]]; then
        echo "::error::Test-Server-Override: '$item' is not <owner>/<repo>#<number> or a pull request URL."
        exit 1
      fi
      refs+=("${BASH_REMATCH[2]} ${BASH_REMATCH[4]}")
    done
  done <<< "$body"

  for item in ${refs[@]+"${refs[@]}"}; do
    read -r repo number <<< "$item"
    remote="https://x-access-token:${REPO_PAT}@github.com/$repo.git"
    sha=$(cd "${RUNNER_TEMP:-/tmp}" && git ls-remote "$remote" "refs/pull/$number/head" | cut -f1)
    if [ -z "$sha" ]; then
      echo "::error::Test-Server-Override: $repo#$number has no head commit, or the token cannot read $repo."
      exit 1
    fi
    if [ "$repo" = "$REPOSITORY" ]; then
      echo "Test-Server-Override: $repo#$number ignored: $repo runs from this pull request's checkout."
      continue
    fi
    if [ "$repo" = "$COMMONS" ]; then
      echo "Test-Server-Override: $repo#$number -> $sha"
      dep_commons=$sha
      continue
    fi
    # The servers clone by branch name, so take the branch at the head commit.
    heads=$(cd "${RUNNER_TEMP:-/tmp}" && git ls-remote --heads "$remote")
    branch=$(awk -v s="$sha" '$1 == s { sub("refs/heads/", "", $2); print $2; exit }' <<< "$heads")
    if [ -z "$branch" ]; then
      echo "::error::Test-Server-Override: $repo#$number: no branch in $repo is at its head commit $sha (pull requests from forks are not supported)."
      exit 1
    fi
    echo "Test-Server-Override: $repo#$number -> $branch ($sha)"
    branches+="$repo $branch"$'\n'
  done

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
