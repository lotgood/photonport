#!/bin/zsh
echo "ERROR: the monorepo GPL-3.0 iOS receiver was retired on 2026-07-22 and exists in git history only (closure receipt: artifacts/cross-repo/ios-retirement-closure.json)." >&2
echo "Use the standalone PhotonPort iOS repository (lotgood/photonport-ios) for all builds and distribution; this script never deletes history or uploads anything." >&2
exit 1
