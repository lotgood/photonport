#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

COMMON=(-parse-as-library -module-cache-path "$TMP/module-cache")
xcrun swiftc "${COMMON[@]}" Mac/Pairing.swift Mac/Log.swift \
  Tests/PairingVectors.swift -o "$TMP/pairing-mac"
xcrun swiftc "${COMMON[@]}" iOS/Pairing.swift iOS/Log.swift \
  Tests/PairingVectors.swift -o "$TMP/pairing-ios"

MAC_VECTOR="$($TMP/pairing-mac)"
IOS_VECTOR="$($TMP/pairing-ios)"
[[ "$MAC_VECTOR" == "$IOS_VECTOR" ]] || {
  echo "pairing vector mismatch between Mac and iOS implementations" >&2
  diff <(print -r -- "$MAC_VECTOR") <(print -r -- "$IOS_VECTOR") >&2 || true
  exit 1
}

print -r -- "pairing vectors match: $MAC_VECTOR"
