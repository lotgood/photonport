#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

COMMON=(-parse-as-library -module-cache-path "$TMP/module-cache")
xcrun swiftc "${COMMON[@]}" Mac/ProtocolParser.swift Mac/Pairing.swift Mac/Log.swift \
  Tests/SessionBindingHarness.swift -o "$TMP/session-mac"
xcrun swiftc "${COMMON[@]}" iOS/Pairing.swift iOS/Log.swift \
  Tests/SessionBindingHarness.swift -o "$TMP/session-ios"

"$TMP/session-mac" >/dev/null
"$TMP/session-ios" >/dev/null
print -r -- "session ownership harness passed (Mac/iOS)"
