#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

# Compiles the shipped Mac pairing/session crypto against the deterministic
# vector harness and pins the output to the canonical cross-implementation
# vector. The standalone iOS receiver (lotgood/photonport-ios) produces the
# byte-identical vector from its own shipped sources; the cross-repo matrix
# runs both harnesses per tuple. The retired monorepo GPL receiver is
# preserved in history only (artifacts/cross-repo/ios-retirement-closure.json).
CANONICAL_VECTOR_SHA256="5dd0e3f8a95697b2c32879a1386a3e6cbe3af4a2c79be6a1735b23a31476fdf2"

COMMON=(-parse-as-library -module-cache-path "$TMP/module-cache")
xcrun swiftc "${COMMON[@]}" Mac/ProtocolParser.swift Mac/Pairing.swift Mac/Log.swift \
  Tests/PairingVectors.swift -o "$TMP/pairing-mac"

MAC_VECTOR="$($TMP/pairing-mac)"
ACTUAL_SHA256="$(print -rn -- "$MAC_VECTOR" | shasum -a 256 | cut -d' ' -f1)"
[[ "$ACTUAL_SHA256" == "$CANONICAL_VECTOR_SHA256" ]] || {
  echo "pairing vector diverged from the canonical cross-implementation vector" >&2
  echo "expected sha256 $CANONICAL_VECTOR_SHA256" >&2
  echo "actual   sha256 $ACTUAL_SHA256" >&2
  exit 1
}

print -r -- "pairing vectors match: $MAC_VECTOR"
