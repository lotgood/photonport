#!/bin/zsh
# Build a Developer ID-signed, notarized PhotonPort DMG + a Sparkle EdDSA
# appcast. Local-only: every signing key stays on this machine. See
# docs/RELEASE.md for credential issuance.
#
# Usage:  ./scripts/release-mac.sh <version>      e.g. ./scripts/release-mac.sh 0.1.0
#
# Required environment (never commit these):
#   DEVELOPMENT_TEAM   Apple team id (also read from .env if present)
#   ASC_KEY_ID         App Store Connect API key id
#   ASC_ISSUER_ID      App Store Connect issuer id
#   ASC_KEY_PATH       path to AuthKey_<id>.p8
#   EXPORT_COMPLIANCE_CONFIRMED=1 only after the Mac export-classification
#                      review is recorded (iOS review is a separate
#                      photonport-ios record and does not gate this script)
# Optional:
#   SPARKLE_BIN        dir containing Sparkle's generate_appcast
#                      (default: search build/SourcePackages artifacts)
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/release-common.sh

VERSION="${1:?usage: release-mac.sh <version>}"
load_local_env
require_release_source "$VERSION"
: "${DEVELOPMENT_TEAM:?set DEVELOPMENT_TEAM (in .env or the environment)}"
: "${ASC_KEY_ID:?set ASC_KEY_ID}"
: "${ASC_ISSUER_ID:?set ASC_ISSUER_ID}"
: "${ASC_KEY_PATH:?set ASC_KEY_PATH (path to AuthKey_*.p8)}"
[[ -f "$ASC_KEY_PATH" ]] || { echo "ASC_KEY_PATH does not exist: $ASC_KEY_PATH" >&2; exit 1; }
require_acknowledgement EXPORT_COMPLIANCE_CONFIRMED \
  "completing and recording the Mac encryption/export-classification review"

BUILD="$(date +%Y%m%d%H%M)"
DIST="dist"
mkdir -p "$DIST"
ARCHIVE="$DIST/PhotonPort-$VERSION.xcarchive"
EXPORT_DIR="$DIST/export-mac-$VERSION"
APP="$EXPORT_DIR/PhotonPort.app"
DMG="$DIST/PhotonPort-$VERSION.dmg"

echo "==> [$VERSION build $BUILD] regenerating project"
./generate.sh

echo "==> archiving (Release, Developer ID)"
rm -rf "$ARCHIVE"
xcodebuild -project OpenSidecar.xcodeproj -scheme OpenSidecarMac \
  -configuration Release -derivedDataPath build -archivePath "$ARCHIVE" \
  MARKETING_VERSION="$VERSION" CURRENT_PROJECT_VERSION="$BUILD" \
  archive

echo "==> exporting signed .app"
EXPORT_PLIST="$DIST/exportOptions-mac.resolved.plist"
sed "s/TEAMID_PLACEHOLDER/$DEVELOPMENT_TEAM/" scripts/exportOptions-mac.plist > "$EXPORT_PLIST"
rm -rf "$EXPORT_DIR"
xcodebuild -exportArchive -archivePath "$ARCHIVE" \
  -exportOptionsPlist "$EXPORT_PLIST" -exportPath "$EXPORT_DIR"
echo "==> verifying exported ProtocolBuildPin resource"
typeset -a BUNDLED_PIN_PATHS
BUNDLED_PIN_PATHS=()
while IFS= read -r -d $'\0' bundled_pin; do
  BUNDLED_PIN_PATHS+=("$bundled_pin")
done < <(find "$APP/Contents/Resources" -type f -name ProtocolBuildPin.json -print0)
[[ ${#BUNDLED_PIN_PATHS} -eq 1 ]] || {
  echo "exported app must contain exactly one ProtocolBuildPin.json resource" >&2
  exit 1
}
cmp -s Mac/ProtocolBuildPin.json "$BUNDLED_PIN_PATHS[1]" || {
  echo "exported ProtocolBuildPin.json does not byte-match Mac/ProtocolBuildPin.json" >&2
  exit 1
}
codesign --verify --deep --strict --verbose=2 "$APP"

echo "==> verifying cross-repo protocol compatibility (live, fail-closed)"
CURRENT_HEAD="$(git rev-parse HEAD)"
IOS_ROOT="${PHOTONPORT_IOS_ROOT:-../photonport-ios}"
PROTOCOL_ROOT="${PHOTONPORT_PROTOCOL_ROOT:-../photonport-protocol}"
IOS_PIN="${PHOTONPORT_IOS_PIN:-Resources/ProtocolBuildPin.json}"
COMPAT_RECEIPT="$DIST/compatibility-report-$VERSION.json"
python3 scripts/verify-cross-repo-compatibility.py \
  --mac-root . --ios-root "$IOS_ROOT" --protocol-root "$PROTOCOL_ROOT" \
  --expected-mac-commit "$CURRENT_HEAD" \
  --expected-ios-commit "$(git -C "$IOS_ROOT" rev-parse HEAD)" \
  --expected-protocol-commit "$(git -C "$PROTOCOL_ROOT" rev-parse HEAD)" \
  --expected-compatibility-digest "$(python3 -c 'import json; print(json.load(open("Mac/ProtocolBuildPin.json"))["compatibilityDigest"])')" \
  --expected-normative-manifest-digest "$(python3 -c 'import json; print(json.load(open("Mac/ProtocolBuildPin.json"))["normativeManifestDigest"])')" \
  --ios-pin "$IOS_PIN" \
  --output "$COMPAT_RECEIPT" || {
  echo "cross-repo compatibility verification failed for HEAD $CURRENT_HEAD; fix the pins/commits before releasing (docs/HANDOFF.md §How to re-verify)" >&2
  exit 1
}
python3 -c '
import json, sys
report = json.load(open(sys.argv[1]))
sys.exit(0 if report.get("result") == "compatible" and report.get("sourceTuple", {}).get("macCommit") == sys.argv[2] else 1)
' "$COMPAT_RECEIPT" "$CURRENT_HEAD" || {
  echo "compatibility receipt did not bind to HEAD $CURRENT_HEAD" >&2
  exit 1
}

echo "==> building DMG (hdiutil)"
rm -f "$DMG"
STAGE="$(mktemp -d)"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT INT TERM
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
cp LICENSE README.md THIRD_PARTY_NOTICES.md ASSETS.md "$STAGE/"
cp -R LICENSES "$STAGE/"
hdiutil create -volname "PhotonPort" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
cleanup
trap - EXIT INT TERM
hdiutil verify "$DMG"

echo "==> notarizing DMG"
xcrun notarytool submit "$DMG" \
  --key "$ASC_KEY_PATH" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID" --wait
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"
echo "==> assessing stapled app bundle (Gatekeeper)"
MOUNT="$(mktemp -d)"
detach_stapled_dmg() {
  hdiutil detach "$MOUNT" >/dev/null 2>&1 || true
  rmdir "$MOUNT" >/dev/null 2>&1 || true
}
trap detach_stapled_dmg EXIT INT TERM
hdiutil attach -nobrowse -readonly -mountpoint "$MOUNT" "$DMG"
MOUNTED_APP="$MOUNT/PhotonPort.app"
[[ -d "$MOUNTED_APP" ]] || {
  echo "mounted DMG does not contain PhotonPort.app" >&2
  exit 1
}
spctl --assess --type exec -vvv "$MOUNTED_APP"
hdiutil detach "$MOUNT"
rmdir "$MOUNT" || true
trap - EXIT INT TERM


echo "==> generating signed appcast (Sparkle EdDSA)"
GEN=""
if [[ -n "${SPARKLE_BIN:-}" && -x "$SPARKLE_BIN/generate_appcast" ]]; then
  GEN="$SPARKLE_BIN/generate_appcast"
else
  GEN="$(find build/SourcePackages -name generate_appcast -type f 2>/dev/null | head -1 || true)"
fi
[[ -n "$GEN" ]] || { echo "generate_appcast not found; set SPARKLE_BIN (see docs/RELEASE.md)" >&2; exit 1; }
KEY_TOOL="$(dirname "$GEN")/generate_keys"
[[ -x "$KEY_TOOL" ]] || { echo "generate_keys not found next to $GEN" >&2; exit 1; }
EXPECTED_PUBLIC_KEY="$(awk '/SUPublicEDKey:/ { print $2; exit }' project.yml)"
ACTUAL_PUBLIC_KEY="$($KEY_TOOL -p)"
[[ "$ACTUAL_PUBLIC_KEY" == "$EXPECTED_PUBLIC_KEY" ]] || {
  echo "Sparkle Keychain key does not match project.yml SUPublicEDKey" >&2
  exit 1
}
"$GEN" "$DIST" \
  --download-url-prefix "https://github.com/lotgood/photonport/releases/download/$PHOTONPORT_RELEASE_TAG/"
python3 scripts/verify-appcast-artifact.py \
  --appcast "$DIST/appcast.xml" \
  --dmg "$DMG" \
  --version "$VERSION" \
  --tag "$PHOTONPORT_RELEASE_TAG" \
  --public-key "$EXPECTED_PUBLIC_KEY"
(
  cd "$DIST"
  shasum -a 256 "$(basename "$DMG")" > "$(basename "$DMG").sha256"
  shasum -a 256 appcast.xml > appcast.xml.sha256
)

echo "==> done"
echo "    DMG:     $DMG"
echo "    appcast: $DIST/appcast.xml"
echo "    source:  https://github.com/lotgood/photonport/tree/$PHOTONPORT_RELEASE_TAG"
echo "Next: publish (docs/RELEASE.md §3)."
