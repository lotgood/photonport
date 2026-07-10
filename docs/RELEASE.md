# PhotonPort Release Runbook (0.1.x)

> Experimental fork. This runbook covers the **local, script-driven** release
> path: a Developer ID–signed & notarized macOS DMG published on GitHub
> Releases (with a Sparkle EdDSA appcast for auto-update) and an iOS build
> uploaded to TestFlight. No CI secrets are used — every signing key stays on
> your machine.

Anchor repository: **`github.com/lotgood/photonport`** (must be **public**).
It hosts the source, the DMG (Releases), the appcast (GitHub Pages), and is the
target of the in-app "Get the Mac app" link (`/releases/latest`).

---

## 0. One-time prerequisites (credential issuance)

You need a **paid Apple Developer account** (the repo's `.env`
`DEVELOPMENT_TEAM` is already set). Then issue three assets.

### 0.1 Developer ID Application certificate (macOS notarization)
The DMG must be signed with a **Developer ID Application** certificate (NOT
"Apple Development" / "Apple Distribution").

- Xcode → Settings → Accounts → your team → **Manage Certificates…** → `+` →
  **Developer ID Application**. Or create it at
  <https://developer.apple.com/account/resources/certificates>.
- Confirm it is installed and valid:
  ```sh
  security find-identity -v -p codesigning | grep "Developer ID Application"
  ```
  Record the exact identity string (e.g. `Developer ID Application: Your Name (TEAMID)`).

### 0.2 App Store Connect API key (.p8) — notarization + TestFlight upload
A single App Store Connect API key drives **both** `notarytool` (Mac notarize)
and `altool` (iOS TestFlight upload).

- <https://appstoreconnect.apple.com> → Users and Access → **Integrations /
  Keys** → App Store Connect API → `+`. Give it **App Manager** access.
- Download the `AuthKey_<KEYID>.p8` **once** (non-recoverable). Note the
  **Key ID** and the **Issuer ID**.
- Store it locally, e.g. `~/.private_keys/AuthKey_<KEYID>.p8`
  (`notarytool` also accepts `--key`, `--key-id`, `--issuer`).

### 0.3 Sparkle EdDSA key (appcast signing)
Sparkle signs each update with an EdDSA (ed25519) key; the app verifies it with
the **public** key baked into `Info.plist` (`SUPublicEDKey`).

- Generate once with Sparkle's tool (from the resolved SwiftPM checkout or a
  downloaded Sparkle release):
  ```sh
  # path may vary; Sparkle ships generate_keys in its bin/ artifacts
  ./bin/generate_keys
  ```
  This stores the **private** key in your login Keychain and prints the
  **public** key (a base64 string).
- The public key is already committed in `project.yml`. Verify that the
  Keychain key still matches before every release:
  ```sh
  ./bin/generate_keys -p
  ```
- A local mode-0600 export was created at
  `~/.private_keys/photonport-sparkle-ed25519.pem`. Move a copy to encrypted
  offline storage; the local path is not a sufficient backup by itself.

> ⚠️ **EdDSA private-key loss is unrecoverable for existing installs.** If you
> lose it you cannot sign updates that current users will accept — they must
> re-download the DMG manually. A rotated key only takes effect for **new**
> installs. Back it up.

---

## 1. Where each asset plugs in

| Asset | Consumed by | How |
|-------|-------------|-----|
| Developer ID Application cert | `scripts/release-mac.sh` → `xcodebuild -exportArchive` | `scripts/exportOptions-mac.plist` (`method: developer-id`) + `$DEVELOPMENT_TEAM` |
| App Store Connect API key (.p8) | `notarytool` (Mac) + `altool` (iOS) | env: `ASC_KEY_ID`, `ASC_ISSUER_ID`, `ASC_KEY_PATH` |
| Sparkle EdDSA private key | `generate_appcast` in `scripts/release-mac.sh` | login Keychain (auto) |
| Sparkle EdDSA public key | app at runtime | `project.yml` `SUPublicEDKey` |
| `$DEVELOPMENT_TEAM` | both release scripts | `.env` (gitignored) |

Environment the scripts expect (export before running, do **not** commit):
```sh
export DEVELOPMENT_TEAM=XXXXXXXXXX
export ASC_KEY_ID=XXXXXXXXXX
export ASC_ISSUER_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export ASC_KEY_PATH=$HOME/.private_keys/AuthKey_XXXXXXXXXX.p8
```

---

## 2. Cut a release (0.1.0)

PhotonPort releases use a namespaced Git tag (`photonport-v0.1.0`) while the
app's marketing version remains `0.1.0`. Do not mirror OpenDisplay release tags
into `origin`; they remain available from the `upstream` remote when historical
comparison is needed.

1. Bump/confirm `MARKETING_VERSION` in `project.yml`, update `CHANGELOG.md`,
   run the protocol-v3 regressions and both unsigned builds, commit, merge to
   `main`, and push so local `origin/main` equals `HEAD`:
   ```sh
   ./scripts/test-pairing-vectors.sh
   ./scripts/test-session-binding.sh
   ./generate.sh
   xcodebuild -project OpenSidecar.xcodeproj -scheme OpenSidecarMac \
     -configuration Debug -derivedDataPath build-mac CODE_SIGNING_ALLOWED=NO build
   xcodebuild -project OpenSidecar.xcodeproj -scheme OpenSidecariOS \
     -configuration Debug -destination 'generic/platform=iOS' \
     -derivedDataPath build-ios CODE_SIGNING_ALLOWED=NO build
   ```
   The device evidence must also reject same/cross-identity takeover, bad
   primary/accept/audio proofs, stale generation/session IDs, replayed audio
   nonces, audio-before-primary timeout, and pre-accept capture/audio. It must
   cover primary cancel, the 5-second receiver timeout, USB replug, and teardown.
2. Obtain and privately record an external export-classification review covering
   **both** the Mac DMG and the iOS/TestFlight build. Apply any required changes,
   rerun step 1, then set `EXPORT_COMPLIANCE_CONFIRMED=1`. This gate blocks both
   distributions; it is separate from the TestFlight-only terms review below.
3. Create the release tag on that exact clean commit, but do not push it yet:
   ```sh
   git tag -s photonport-v0.1.0 -m "PhotonPort 0.1.0"
   ```
   Use an annotated tag if a signing key is not configured. Do not substitute
   an unnamespaced tag such as `v0.1.0`.
4. Build the notarized DMG + signed appcast:
   ```sh
   ./scripts/release-mac.sh 0.1.0
   ```
   Verify codesign, Gatekeeper, notarization/stapling, checksums, appcast URL,
   EdDSA signature, and the embedded Sparkle public key against the private key.
5. **AC#9 runtime smoke (blocking):** install this exact notarized candidate on
   the supported Mac and run one USB Mac↔iPad session covering virtual display,
   capture, input, audio, disconnect/reconnect, and replug. Confirm redacted
   `CapabilityProbe` and session-v3 reason logs are healthy.
6. On any failure, delete the unpublished local tag and candidate artifacts, fix
   on a new commit, and restart. On success, push the tag, create and verify a
   draft GitHub Release, publish it, then verify Pages, `releases/latest`, the DMG
   URL, and the appcast before announcing. If the release-triggered Pages deploy
   is blocked or the feed is stale, run **Actions → Pages → Run workflow** from
   `main` with the exact published `photonport-v*` tag; invalid or unpublished tags
   fail closed.
7. Before any TestFlight upload, obtain and privately record the separate external
   GPL-3.0/Apple/TestFlight terms review and App Privacy determination. Only this
   iOS gate permits `APPLE_DISTRIBUTION_TERMS_REVIEWED=1`; it does not gate the Mac
   GitHub Release once the export review and Mac evidence are complete.
8. Build and upload the internal TestFlight candidate:
   ```sh
   ./scripts/release-ios.sh 0.1.0
   ```
   Verify processing, privacy metadata, and the recorded export-compliance state.

The build number (`CURRENT_PROJECT_VERSION`) is injected by the scripts as a
date stamp (`YYYYMMDDHHMM`) to keep TestFlight builds monotonic.

---

## 3. Publish checklist (manual, GitHub)

- [ ] Confirm `github.com/lotgood/photonport` remains **public** and the release
      commit is pushed to `origin/main`.
- [ ] Repo → Settings → Pages uses **GitHub Actions**. Before the first PhotonPort
      release, `privacy.html` must return 200 and `appcast.xml` is expected to be
      absent; privacy-only pushes must not fabricate an appcast.
- [ ] Repo → Settings → Environments → `github-pages` permits deployment tags
      matching `photonport-v*` in addition to the default branch. Without this
      rule, the release-published event can be rejected before deployment; the
      validated manual-dispatch path from `main` is the recovery route.
- [ ] Create a draft GitHub Release **`photonport-v0.1.0`**. Attach
      `PhotonPort-0.1.0.dmg`, its `.sha256`, `appcast.xml`, and
      `appcast.xml.sha256`, then publish. The DMG download URL must match
      `generate_appcast --download-url-prefix`
      (`.../releases/download/photonport-v0.1.0/`).
- [ ] Verify the in-app link: `.../releases/latest` returns **200** and shows
      the DMG.
- [ ] Verify `privacy.html` and `appcast.xml` on Pages return **200**. Confirm the
      deployed appcast checksum and selected-tag enclosure; CI covers privacy push,
      namespaced/non-namespaced release, and dispatch selection semantics.
- [ ] TestFlight: internal testers first (no review); expand to an external
      public link only after Beta App Review.

---

## 4. Acceptance criteria (verify before "done")

- AC#1 `spctl -a -vvv PhotonPort.app` = **accepted** on a clean Mac.
- AC#2 For the first binary release, manual update-check verifies and downloads
  the signed `0.1.0` appcast. Full old→new update testing begins with `0.1.1`.
- AC#3 In-app "Get the Mac app" → `releases/latest` returns 200.
- AC#4 iOS `0.1.0` processes on TestFlight, has an accepted privacy manifest,
  and shows the expected recorded export-compliance state.
- AC#5 `MARKETING_VERSION=0.1.0`, date-based build number, CHANGELOG section present.
- AC#6 Protocol-v3 vectors, session ownership/replay harness, and unsigned builds
  stay green for both targets.
- AC#7 README keeps the EXPERIMENTAL / single-hardware-pair framing and accurately
  distinguishes receiver binding from the remaining stolen-PSK/no-PFS risks.
- AC#8 Release artifacts/credentials are ignored; LICENSE, third-party notices,
  and asset notices ship with the DMG.
- AC#9 (**blocking**) the supported-device USB runtime smoke passes on the exact
  notarized candidate before the Mac release is published.
- AC#10 Export review covers Mac and iOS before either distribution; the separate
  GPL/Apple/TestFlight terms review is complete before the iOS upload.

## 5. Distribution compliance records

Maintain two private records with distinct approval scopes:

1. **Export classification (Mac and iOS):** the exact CryptoKit/TLS-PSK/session-v3
   functionality reviewed; Mac DMG and iOS/TestFlight distribution scope; Apple
   encryption answers and any declaration, exemption, approval code, or required
   changes; reviewer/conclusion/date; release commit and version.
2. **GPL/Apple/TestFlight terms (iOS only):** the GPL-3.0-only derivative and
   Apple/TestFlight terms conclusion, intended internal-TestFlight scope, privacy
   policy URL, App Privacy answers, reviewer/conclusion/date, commit and version.

The release evidence record additionally captures tag, certificate identity,
notarization submission ID, checksums, appcast digest/signature verification,
Pages URLs, and the supported-hardware AC#9 result. Environment acknowledgements
are local guardrails, not legal or export advice, and never substitute for these
records.
