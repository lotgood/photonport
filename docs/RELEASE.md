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
   run all tests/builds, commit, merge to `main`, and push so local
   `origin/main` equals `HEAD`.
2. Create the release tag on that exact clean commit:
   ```sh
   git tag -s photonport-v0.1.0 -m "PhotonPort 0.1.0"
   ```
   Use an annotated tag if a signing key is not configured. Do not substitute
   an unnamespaced tag such as `v0.1.0`.
3. Build the notarized DMG + signed appcast:
   ```sh
   ./scripts/release-mac.sh 0.1.0
   ```
   Outputs the DMG, appcast, and SHA-256 files in `dist/`.
4. Complete Apple's encryption/export questionnaire and review GPL-3.0 versus
   Apple/TestFlight distribution terms. Record the result, then explicitly
   acknowledge both local release gates:
   ```sh
   export EXPORT_COMPLIANCE_CONFIRMED=1
   export APPLE_DISTRIBUTION_TERMS_REVIEWED=1
   ```
5. Build & upload the iOS TestFlight build:
   ```sh
   ./scripts/release-ios.sh 0.1.0
   ```
6. **Publish** (see §3): push the namespaced tag, create a draft GitHub Release,
   attach every required artifact, then publish it. Publishing triggers the
   Pages workflow that deploys the privacy policy and appcast.
7. **Runtime smoke (blocking):** install the notarized DMG on a clean
   Mac, run one USB Mac↔iPad session (virtual display + capture + input +
   audio), and confirm `CapabilityProbe` logs are healthy **before** announcing.

The build number (`CURRENT_PROJECT_VERSION`) is injected by the scripts as a
date stamp (`YYYYMMDDHHMM`) to keep TestFlight builds monotonic.

---

## 3. Publish checklist (manual, GitHub)

- [ ] Make `github.com/lotgood/photonport` **public** and `git push`.
- [ ] Repo → Settings → Pages → set source to **GitHub Actions**. Confirm
      `https://lotgood.github.io/photonport/appcast.xml` serves.
- [ ] Create a draft GitHub Release **`photonport-v0.1.0`**. Attach
      `PhotonPort-0.1.0.dmg`, its `.sha256`, `appcast.xml`, and
      `appcast.xml.sha256`, then publish. The DMG download URL must match
      `generate_appcast --download-url-prefix`
      (`.../releases/download/photonport-v0.1.0/`).
- [ ] Verify the in-app link: `.../releases/latest` returns **200** and shows
      the DMG.
- [ ] Verify `privacy.html` and `appcast.xml` on Pages return **200**.
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
- AC#6 Unsigned `build.yml` stays green for both targets.
- AC#7 README keeps the EXPERIMENTAL / single-hardware-pair framing.
- AC#8 Release artifacts/credentials are ignored; LICENSE, third-party notices,
  and asset notices ship with the DMG.
- AC#9 (**blocking**) runtime smoke on the actual release OS passes before going public.

## 5. Distribution compliance record

Before setting either acknowledgement variable, save a private record of:

- the App Store Connect encryption answers and any declaration/approval code;
- the exact CryptoKit/TLS functionality reviewed;
- the GPL-3.0 and Apple/TestFlight terms review conclusion;
- the privacy policy URL and App Privacy answers;
- the release commit, tag, certificate identity, notarization submission ID,
  checksums, and hardware smoke-test result.

The acknowledgement variables are guardrails, not legal or export advice.
