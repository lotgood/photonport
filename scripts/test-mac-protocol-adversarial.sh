#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

# Pairing.swift, ProtocolParser.swift, and ScrollEventCoalescer.swift are shipped
# implementations; the harness supplies deterministic assertions and I/O.
xcrun swiftc -parse-as-library -module-cache-path "$TMP/module-cache" \
  Mac/ScrollEventCoalescer.swift Mac/ProtocolParser.swift Mac/Pairing.swift Mac/Log.swift Tests/MacProtocolAdversarialHarness.swift \
  -o "$TMP/mac-protocol-adversarial"
"$TMP/mac-protocol-adversarial" "$@"
[[ $# -eq 0 ]] && print -r -- "mac protocol adversarial harness passed"
