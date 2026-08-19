#!/usr/bin/env python3
"""Reconcile a Language_Repository's merged bug FIXES into the commons base ledger.

A Language_Repository declares the base-ledger bugs its target has fixed in its
commons-configuration.json ``knownBugFixOverrides`` array. Once that fix is merged to the
repository's main branch, the commons ``known-bugs.json`` (the authoritative
list) should stop attributing those bugs to that target. This script performs
that removal so a workflow can open the reconciling PR against commons.

Resolution: the calling repository owns one Configuration_Entry per
commons-configuration.json it ships (identified by ``commonsConfigurationPath``,
or the default path). Each entry's target identity is
``(language, majorVersion, libraryRepository.name)`` — the same triple the base
ledger keys on. For every bug id in that repo's ``knownBugFixOverrides``, the entry's target
is removed from the bug; a bug left with no targets is dropped entirely.

Idempotent: a fixed id the ledger does not attribute to the target (or no longer
defines) is a silent no-op, so re-running never fails and never over-removes.

Exit status: 0 if the ledger was changed (a PR is warranted), 1 if nothing
changed, 2 on a usage/IO error. Writes the updated ledger in place when changed.
"""

import argparse
import json
import sys
from pathlib import Path

DEFAULT_COMMONS_CONFIG_PATH = "esdk/test-server/commons-configuration.json"


def _load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def resolve_targets(config_set, repo_name, commons_config_path):
    """The (language, majorVersion, repository) triples the caller repo owns.

    Matches Configuration_Entries whose libraryRepository is ``repo_name`` and
    whose commons-configuration path equals ``commons_config_path`` (the default
    when an entry sets none). A repo that hosts several servers (e.g.
    aws-encryption-sdk: net/rust-dafny/go) owns several entries, each at its own
    path, so pinning the path selects exactly the one the merged file belongs to.
    """
    targets = []
    for entry in config_set.get("entries", []):
        library = (entry.get("libraryRepository") or {}).get("name")
        if library != repo_name:
            continue
        entry_path = entry.get("commonsConfigurationPath") or DEFAULT_COMMONS_CONFIG_PATH
        if entry_path != commons_config_path:
            continue
        targets.append(
            (entry.get("language"), entry.get("majorVersion"), library)
        )
    return targets


def reconcile(ledger, targets, fixed_ids):
    """Remove each target from every fixed bug; drop emptied entries.

    Returns the list of ``(bug_id, target)`` removals actually applied (empty
    when nothing changed), and mutates ``ledger`` in place.
    """
    removals = []
    for language, major_version, repository in targets:
        for bug in ledger:
            if bug.get("id") not in fixed_ids:
                continue
            kept = [
                t
                for t in bug.get("targets", [])
                if not (
                    t.get("language") == language
                    and t.get("majorVersion") == major_version
                    and t.get("repository") == repository
                )
            ]
            if len(kept) != len(bug.get("targets", [])):
                bug["targets"] = kept
                removals.append((bug["id"], f"{language}-v{major_version} in {repository}"))
    if removals:
        ledger[:] = [bug for bug in ledger if bug.get("targets")]
    return removals


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True,
                        help="path to the commons known-bugs.json to reconcile")
    parser.add_argument("--config-set", required=True,
                        help="path to the commons configuration-set.json")
    parser.add_argument("--repo", required=True,
                        help="calling repository name, e.g. aws-crypto-tools-java")
    parser.add_argument("--commons-config", required=True,
                        help="path to the calling repo's merged commons-configuration.json")
    parser.add_argument("--commons-config-path", required=True,
                        help="the repo-root-relative path of that file "
                             "(its commonsConfigurationPath in configuration-set.json)")
    args = parser.parse_args(argv)

    try:
        ledger = _load(args.ledger)
        config_set = _load(args.config_set)
        commons_config = _load(args.commons_config)
    except (OSError, json.JSONDecodeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    fixed_ids = set(commons_config.get("knownBugFixOverrides") or [])
    if not fixed_ids:
        print("no knownBugFixOverrides declared; nothing to reconcile")
        return 1

    targets = resolve_targets(config_set, args.repo, args.commons_config_path)
    if not targets:
        print(f"error: no configuration-set entry for repo '{args.repo}' at "
              f"'{args.commons_config_path}'", file=sys.stderr)
        return 2

    removals = reconcile(ledger, targets, fixed_ids)
    if not removals:
        print("base ledger already reconciled; nothing to change")
        return 1

    Path(args.ledger).write_text(
        json.dumps(ledger, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for bug_id, target in removals:
        print(f"removed {target} from bug '{bug_id}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
