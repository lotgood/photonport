# PhotonPort Release Runbook (0.1.x)

> Experimental fork. This runbook covers the **local, script-driven** Mac
> release path: a Developer ID–signed & notarized macOS DMG published on GitHub
> Releases (with a Sparkle EdDSA appcast for auto-update). The standalone
> [photonport-ios](https://github.com/lotgood/photonport-ios) repository is the
> post-transition iOS build and distribution authority. The monorepo iOS target
> and `scripts/release-ios.sh` are retained only for historical reproducibility,
> provenance, and rollback; they are not the steady-state App Store path.
> No publication, signing, export approval, or TestFlight approval is evidenced
> by this document.

Anchor repository: **`github.com/lotgood/photonport`** (must be **public**).
It hosts the source, the DMG (Releases), the appcast (GitHub Pages), and is the
target of the in-app "Get the Mac app" link (`/releases/latest`).
The exact compatibility manifest for every candidate is protocol **3.0.0**,
pairing **2.0.0**, Mac minimum **0.1.0**, and standalone iOS minimum **1.0.0**;
mismatches must fail closed with an upgrade message. The only supported
hardware pair is an **M4 Max Mac on macOS 27 over USB with an iPad Pro 11-inch
M4 on iPadOS 27**. Runs on other OS versions are not evidence and remain
unverified.

The split is fail-closed and ordered: preserve the monorepo iOS target; complete
physical G004; capture provenance G006; prove rollback; obtain separate Mac and
iOS export-classification reviews; complete Mac signing/notarization and iOS
signing/TestFlight records; then complete publication and URL/repository
receipts. The monorepo iOS target must not be retired before every gate has
evidence. No step below grants external approval or claims publication.
## License and release authority
- This repository's Mac sender and historical iOS source remain GPL-3.0-only.
- Standalone `photonport-ios` and `photonport-protocol` are MIT-licensed and
  have separate release authorities; their licenses do not relicense this
  repository's history.
- Mac export classification, Developer ID signing, notarization, Sparkle
  receipts, GitHub Release, and Pages receipts belong to the Mac release record.
- iOS export classification, App Store/TestFlight terms, App Privacy,
  distribution signing, TestFlight processing, and publication receipts belong
  to the standalone iOS release record.
- Keep the monorepo iOS artifacts as rollback/provenance evidence; do not
  present them as the standalone iOS candidate.

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

### 0.2 App Store Connect API key (.p8) — Mac notarization and standalone iOS

A single App Store Connect API key may be used by the Mac `notarytool` flow
and by the standalone iOS release authority, but credentials and receipts remain
separate and are never committed.

- <https://appstoreconnect.apple.com> → Users and Access → **Integrations /
  Keys** → App Store Connect API → `+`. Give it **App Manager** access.
- Download the `AuthKey_<KEYID>.p8` **once** (non-recoverable). Note the
  **Key ID** and the **Issuer ID**.
- Store it locally, e.g. `~/.private_keys/AuthKey_<KEYID>.p8`
  (`notarytool` also accepts `--key`, `--key-id`, `--issuer`).

### 0.3 Sparkle EdDSA key and tools (appcast signing)

Sparkle signs each update with an EdDSA (ed25519) key; the app verifies it with
the **public** key baked into `Info.plist` (`SUPublicEDKey`).

- Build the project once so SwiftPM resolves Sparkle, then locate the directory
  containing both `generate_appcast` and `generate_keys` under the generated
  `build/SourcePackages` artifacts. Alternatively, install a Sparkle release
  that provides both tools and set `SPARKLE_BIN` to that directory. The release
  script searches the build artifacts only when `SPARKLE_BIN` is unset.
- Generate the key once with that directory's `generate_keys`. It stores the
  **private** key in the login Keychain and prints the **public** base64 key.
  The public key is already committed in `project.yml`; run
  `generate_keys -p` before each release and require an exact match.
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
| App Store Connect API key (.p8) | Mac `notarytool`; standalone iOS release authority | env: `ASC_KEY_ID`, `ASC_ISSUER_ID`, `ASC_KEY_PATH`; never commit |
| Sparkle EdDSA private key | `generate_appcast` in `scripts/release-mac.sh` | login Keychain (auto) |
| Sparkle EdDSA public key | Mac app at runtime | `project.yml` `SUPublicEDKey` |
| `$DEVELOPMENT_TEAM` | Mac release and standalone iOS release records | `.env` (gitignored); ownership and receipts remain separate |

Environment the scripts require (export before running, do **not** commit):
```sh
export DEVELOPMENT_TEAM=XXXXXXXXXX
export ASC_KEY_ID=XXXXXXXXXX
export ASC_ISSUER_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export ASC_KEY_PATH=$HOME/.private_keys/AuthKey_XXXXXXXXXX.p8
# Set only after the Mac export-classification review is recorded.
export EXPORT_COMPLIANCE_CONFIRMED=1
# Optional: directory containing both generate_appcast and generate_keys.
export SPARKLE_BIN=/path/to/Sparkle/bin
```

`SPARKLE_BIN` is optional; see §0.3 for the build-artifact discovery path.
`EXPORT_COMPLIANCE_CONFIRMED=1` is a local fail-closed acknowledgement, not
evidence that an export review was approved.

---

## 2. Cut a release (0.1.0)

PhotonPort releases use a namespaced Git tag (`photonport-v0.1.0`) while the
app's marketing version remains `0.1.0`. Do not mirror OpenDisplay release tags
into `origin`; they remain available from the `upstream` remote when historical
comparison is needed.

1. Bump/confirm `MARKETING_VERSION` in `project.yml`, update `CHANGELOG.md`,
   and keep the Mac sender commit clean and reproducible. The Mac-only unsigned
   build and protocol checks are historical verification commands:
   `./scripts/test-pairing-vectors.sh`, `./scripts/test-session-binding.sh`,
   `./generate.sh`, and the `OpenSidecarMac` unsigned `xcodebuild` command.
   The old monorepo `OpenSidecariOS` unsigned build remains available only for
   rollback/provenance; it is not the transitioned iOS release candidate.
2. For the Mac DMG, obtain and privately record the Mac export-classification
   review. Apply required changes and record the reviewer, conclusion, date,
   exact commit, version, and any Apple declaration or exemption. Set
   `EXPORT_COMPLIANCE_CONFIRMED=1` only after that record exists. This blocks
   Mac distribution.
3. Separately obtain and privately record the standalone iOS
   export-classification review covering CryptoKit/TLS-PSK/session-v3. This is
   an iOS distribution record, may proceed in parallel, and does **not** gate
   the Mac GitHub Release.
4. **Before running `release-mac.sh`, push the exact clean release commit to
   `origin/main`, then create its signed annotated release tag locally.**
   `release-common.sh` requires `HEAD == origin/main`; the release *tag*, not
   the release commit, is what remains unpublished at this point:
   ```sh
   git push origin HEAD:main
   git fetch origin
   test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
   git tag -s photonport-v0.1.0 -m "PhotonPort 0.1.0"
   git verify-tag photonport-v0.1.0
   ```
   Do not push the tag yet. `release-common.sh` rejects unsigned or
   unverifiable tags with `git verify-tag`.
5. Build the notarized Mac DMG and signed appcast:
   ```sh
   ./scripts/release-mac.sh 0.1.0
   ```
   After export, the script fails closed before DMG construction unless
   `artifacts/cross-repo/compatibility-report.json` is `compatible`, binds the
   committed-tree Mac snapshot to `HEAD`, and has `identity=committed_tree`.
   That same post-export phase requires exactly one `ProtocolBuildPin.json` in
   the exported app and byte-compares it with `Mac/ProtocolBuildPin.json`.
   After stapling, it mounts the DMG and runs `spctl --assess --type exec -vvv`
   on the mounted `PhotonPort.app`; Gatekeeper acceptance is therefore
   automated. It then
   verifies the generated appcast with
   `scripts/verify-appcast-artifact.py`: the exact version/tag enclosure URL,
   `sparkle:shortVersionString`, and the real Ed25519 signature over the DMG
   bytes against `project.yml` `SUPublicEDKey`. The success banner appears only
   after every check passes.
6. **AC#9 runtime smoke (blocking):** install this exact notarized Mac candidate
   on the supported macOS 27 Mac. Complete the eight-item USB checklist:
   `usb_display`, `usb_hdr`, `usb_120hz`, `usb_audio`, `usb_rotation`,
   `usb_input`, `usb_disconnect`, and `usb_replug`. Retain the checklist and
   `/tmp/photonport-mac.log` lines for the session-v3 accept and end reason.
   Runs on other OS versions do not satisfy this gate.
7. On any failure, delete the unpublished local tag and candidate artifacts, fix
   on a new commit, and restart. On success, push the verified signed tag,
   create and verify a draft GitHub Release, publish it, then verify Pages,
   `releases/latest`, the DMG URL, and the appcast before announcing. If the
   release-triggered Pages deploy is blocked or the feed is stale, run
   **Actions → Pages → Run workflow** from `main` with the exact published
   `photonport-v*` tag; invalid or unpublished tags fail closed.
8. Before any standalone iOS TestFlight upload, obtain and privately record the
   separate GPL-3.0/Apple/TestFlight terms review and App Privacy determination.
   Only the `photonport-ios` release tooling consumes
   `APPLE_DISTRIBUTION_TERMS_REVIEWED=1`; this repository's scripts do not.
   This iOS acknowledgement does not gate the Mac GitHub Release.
9. Build and upload the iOS candidate only from the standalone
   [photonport-ios repository](https://github.com/lotgood/photonport-ios), using
   its own signing, TestFlight, privacy, and export receipts. The monorepo
   `scripts/release-ios.sh` command is historical context and rollback tooling,
   not the intended steady-state App Store path.

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

### Mac distribution blockers

Every row in this table, including the Mac export record, blocks publication of
the Mac GitHub Release.

| Criterion | Required evidence |
|---|---|
| Mac export classification | Private record for the exact Mac commit/version: reviewer, conclusion/date, Apple declaration or exemption, and required changes. `EXPORT_COMPLIANCE_CONFIRMED=1` may be set only after this record. |
| AC#1 | `release-mac.sh` completes its mounted-DMG Gatekeeper assessment (`spctl --assess --type exec -vvv`); the script does not require a separate manual Gatekeeper step. |
| AC#2 | Manual update-check log contains the signature-verified line for the signed `0.1.0` appcast **and** a screenshot of that successful update check. Full old→new update testing begins with `0.1.1`. |
| AC#3 | In-app **Get the Mac app** opens `releases/latest`; retain an HTTP 200 check or browser evidence showing the DMG. |
| AC#5 | `MARKETING_VERSION=0.1.0`, a date-based build number, and the matching `CHANGELOG.md` section. |
| AC#8 | Release artifacts and credentials are ignored, and the mounted DMG contains exactly these required notice payloads: `LICENSE`, `README.md`, `THIRD_PARTY_NOTICES.md`, `ASSETS.md`, and `LICENSES/`. |
| AC#9 | The exact notarized candidate passes the eight USB checks in §2 step 7; retain that checklist plus `/tmp/photonport-mac.log` session-v3 accept and end-reason lines. |

The G004 WiFi scenarios have a narrower scope: `wifi_unpaired` and
`wifi_takeover` are required before a Mac public release. `wifi_wrong_mac`
remains `not_run` until a second Mac is available; it blocks only retirement of
the monorepo iOS target (`retirementEligible`), not Mac DMG distribution.

### Standalone iOS distribution records (do not gate the Mac GitHub Release)

These entries belong to the standalone iOS authority and must not be used to
claim that the Mac release approved or published iOS.

| Criterion | Required evidence |
|---|---|
| AC#4 | App Store Connect screenshot showing the TestFlight build state transition **Processing → Ready** and the recorded export-compliance field; retain the accepted privacy-manifest record. |
| AC#6 (iOS portion) | `artifacts/cross-repo/automated-matrix.json` has `"result": "passed"` **and** the corresponding green CI run URL is retained. |
| AC#10 (iOS portion) | Independent standalone-iOS export review plus provenance/legal, Apple/TestFlight terms, signing, and upload records for the exact iOS candidate. |

### Shared documentation record

| Criterion | Required evidence |
|---|---|
| AC#7 | README's Security section separately states receiver binding, the stolen-PSK residual risk, and the no-forward-secrecy residual risk. |

## 5. Distribution compliance records

Maintain private records with distinct approval scopes:

1. **Mac export classification:** exact CryptoKit/TLS-PSK/session-v3
   functionality reviewed for the Mac DMG; Apple encryption answers and any
   declaration, exemption, approval code, or required changes; reviewer,
   conclusion/date, release commit, version, Developer ID identity,
   notarization receipt, checksums, appcast digest/signature, and Pages URLs.
2. **Standalone iOS export classification:** the same functionality reviewed
   for the standalone iOS/TestFlight distribution, with its own Apple answers,
   reviewer/conclusion/date, commit, version, and receipt.
3. **Standalone iOS provenance/legal and Apple/TestFlight record:** MIT source and
   notice completeness, App Store/TestFlight distribution terms, intended internal
   TestFlight scope, privacy policy URL, App Privacy answers, reviewer/conclusion/date,
   commit, version, signing identity, and TestFlight processing receipt.

No record is complete from an environment variable or an internal assertion;
external approval and publication must be evidenced separately.

The release evidence record additionally captures tag, certificate identity,
notarization submission ID, checksums, appcast digest/signature verification,
Pages URLs, and the supported-hardware AC#9 result. Environment acknowledgements
are local guardrails, not legal or export advice, and never substitute for these
records.
