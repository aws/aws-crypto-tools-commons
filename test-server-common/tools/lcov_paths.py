#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Keep only one repository's files in an lcov report, with repo-relative paths.

Usage: lcov_paths.py <clone> < in.lcov > out.lcov

<clone> is the repository's directory relative to the workspace, such as
`language-repo` or `esdk/test-server/build/sources/<name>`. The server was
compiled on another runner, whose workspace path can differ, so a source path
is matched on `/<clone>/` rather than on an absolute prefix. Records for files
outside the clone (dependencies, the standard library) are dropped.
"""

import sys


def main() -> None:
    marker = "/" + sys.argv[1].strip("/") + "/"
    keep = False
    for line in sys.stdin:
        if line.startswith("SF:"):
            at = line.find(marker)
            keep = at >= 0
            if keep:
                line = "SF:" + line[at + len(marker):]
        if keep:
            sys.stdout.write(line)
            if line.startswith("end_of_record"):
                keep = False


if __name__ == "__main__":
    main()
