#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

# Pairing.swift is the shipped implementation; the harness supplies only
# deterministic assertions and pure adapters for framework-independent bounds.
xcrun swiftc -parse-as-library -module-cache-path "$TMP/module-cache" \
  Mac/Pairing.swift Mac/Log.swift Tests/MacProtocolAdversarialHarness.swift \
  -o "$TMP/mac-protocol-adversarial"
"$TMP/mac-protocol-adversarial"
print -r -- "mac protocol adversarial harness passed"
