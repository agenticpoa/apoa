#!/usr/bin/env bash
# Extract a single release section from CHANGELOG.md.
#
# Usage: extract-changelog.sh <package> <version>
#   <package>: "apoa" or "@apoa/core"
#   <version>: e.g. "0.2.0"
#
# Matches both dedicated headers (## `apoa` 0.2.0 — ...) and combined
# headers (## `@apoa/core` 0.1.1 / `apoa` 0.1.1 — ...). Prints the
# section body (without the heading) to stdout.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <package> <version>" >&2
  exit 2
fi

pkg=$1
version=$2

awk -v pkg="$pkg" -v ver="$version" '
  function match_header() {
    # Match `## \`<pkg>\` <version>` anywhere in the heading line
    # (covers both standalone and combined release headers).
    return $0 ~ ("^## .*`" pkg "` " ver "([^0-9]|$)")
  }
  /^## / {
    if (in_section) exit
    if (match_header()) { in_section = 1; next }
  }
  /^---$/ { if (in_section) next }
  in_section { print }
' CHANGELOG.md | awk '
  # Trim leading and trailing blank lines.
  /^$/ { if (!seen) next; blanks = blanks "\n"; next }
  { seen = 1; printf "%s%s\n", blanks, $0; blanks = "" }
'
