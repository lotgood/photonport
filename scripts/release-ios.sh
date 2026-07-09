#!/bin/zsh
# Build a Release iOS archive and upload it to TestFlight. Local-only.
# See docs/RELEASE.md for credential issuance.
#
# Usage:  ./scripts/release-ios.sh <version>      e.g. ./scripts/release-ios.sh 0.1.0
#
# Required environment (never commit these):
#   DEVELOPMENT_TEAM   Apple team id (also read from .env if present)
#   ASC_KEY_ID         App Store Connect API key id
#   ASC_ISSUER_ID      App Store Connect issuer id
#   ASC_KEY_PATH       path to AuthKey_<id>.p8
#   EXPORT_COMPLIANCE_CONFIRMED=1 after completing Apple's encryption flow
#   APPLE_DISTRIBUTION_TERMS_REVIEWED=1 after reviewing GPL/Apple terms
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/release-common.sh

VERSION="${1:?usage: release-ios.sh <version>}"
load_local_env
require_release_source "$VERSION"
: "${DEVELOPMENT_TEAM:?set DEVELOPMENT_TEAM (in .env or the environment)}"
: "${ASC_KEY_ID:?set ASC_KEY_ID}"
: "${ASC_ISSUER_ID:?set ASC_ISSUER_ID}"
: "${ASC_KEY_PATH:?set ASC_KEY_PATH (path to AuthKey_*.p8)}"
[[ -f "$ASC_KEY_PATH" ]] || { echo "ASC_KEY_PATH does not exist: $ASC_KEY_PATH" >&2; exit 1; }
require_acknowledgement EXPORT_COMPLIANCE_CONFIRMED \
  "completing and recording Apple's encryption/export-compliance determination"
require_acknowledgement APPLE_DISTRIBUTION_TERMS_REVIEWED \
  "reviewing GPL-3.0 and Apple/TestFlight distribution terms"
plutil -lint iOS/PrivacyInfo.xcprivacy

BUILD="$(date +%Y%m%d%H%M)"
DIST="dist"
mkdir -p "$DIST"
ARCHIVE="$DIST/PhotonPort-iOS-$VERSION.xcarchive"
EXPORT_DIR="$DIST/export-ios-$VERSION"

echo "==> [$VERSION build $BUILD] regenerating project"
./generate.sh

echo "==> archiving (Release, iOS)"
rm -rf "$ARCHIVE"
xcodebuild -project OpenSidecar.xcodeproj -scheme OpenSidecariOS \
  -configuration Release -destination 'generic/platform=iOS' \
  -derivedDataPath build -archivePath "$ARCHIVE" \
  MARKETING_VERSION="$VERSION" CURRENT_PROJECT_VERSION="$BUILD" \
  -allowProvisioningUpdates archive

echo "==> exporting IPA (app-store)"
EXPORT_PLIST="$DIST/exportOptions-ios.plist"
cat > "$EXPORT_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>app-store-connect</string>
    <key>teamID</key>
    <string>$DEVELOPMENT_TEAM</string>
    <key>signingStyle</key>
    <string>automatic</string>
    <key>destination</key>
    <string>export</string>
</dict>
</plist>
PLIST
rm -rf "$EXPORT_DIR"
xcodebuild -exportArchive -archivePath "$ARCHIVE" \
  -exportOptionsPlist "$EXPORT_PLIST" -exportPath "$EXPORT_DIR" \
  -allowProvisioningUpdates

IPA="$(find "$EXPORT_DIR" -name '*.ipa' -type f | head -1)"
[[ -n "$IPA" ]] || { echo "no .ipa produced in $EXPORT_DIR" >&2; exit 1; }

echo "==> uploading to TestFlight (altool, ASC API key)"
# altool resolves the .p8 by key id from these dirs; point it at ASC_KEY_PATH's dir.
export API_PRIVATE_KEYS_DIR="$(dirname "$ASC_KEY_PATH")"
xcrun altool --upload-app -f "$IPA" -t ios \
  --apiKey "$ASC_KEY_ID" --apiIssuer "$ASC_ISSUER_ID"

echo "==> done: uploaded $IPA to TestFlight (internal testers first; see docs/RELEASE.md §3)"
