#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

# Pairing.swift and ProtocolParser.swift are the shipped implementation; the
# harness supplies only deterministic assertions and process/file I/O.
xcrun swiftc -parse-as-library -module-cache-path "$TMP/module-cache" \
  Mac/ProtocolParser.swift Mac/Pairing.swift Mac/Log.swift Tests/MacProtocolAdversarialHarness.swift \
  -o "$TMP/mac-protocol-adversarial"
"$TMP/mac-protocol-adversarial"
print -r -- "mac protocol adversarial harness passed"
