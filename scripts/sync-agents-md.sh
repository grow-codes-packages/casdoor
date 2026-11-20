#!/bin/sh
# Copies docs/agents-api.md into every package artifact as AGENTS.md (npm files, Go module root,
# wheel package data, crate include, jar resources). Run after editing docs/agents-api.md;
# CI-friendly check: scripts/sync-agents-md.sh --check
set -eu
cd "$(dirname "$0")/.."
src=docs/agents-api.md
targets="typescript/AGENTS.md go/AGENTS.md python/src/grow_casdoor/AGENTS.md rust/AGENTS.md java/src/main/resources/META-INF/grow/casdoor/AGENTS.md"
status=0
for t in $targets; do
  if [ "${1:-}" = "--check" ]; then
    cmp -s "$src" "$t" || { echo "out of date: $t"; status=1; }
  else
    cp "$src" "$t"
  fi
done
exit $status
