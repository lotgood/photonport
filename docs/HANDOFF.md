# PhotonPort handoff — state and remaining gates

Last updated: 2026-07-22. This file is the single entry point for picking the
release work back up. On this date the authenticated-wire refactor was
completed, physically verified against the tested pair, and extended with
canonical ProRes 422; every automated suite and the cross-repo matrix are
green at the tuple below. Nothing here evidences external approval, signing,
notarization, or publication. Machine-readable receipts live under
`artifacts/`; durable goal state lives in `.gjc/ultragoal/` (local, not
committed).

## Current source tuple and branch layout (2026-07-22)

| Repository | Branch | Commit | Notes |
|---|---|---|---|
| `lotgood/photonport` | `refactor/complete` | matrix tuple `9278aad` + evidence/docs commits above it | ahead of `origin/main`; branch not yet pushed |
| `lotgood/photonport-ios` | `refactor/complete` | `a56d223` (matrix tuple `cb6e9ac`) | pushed 2026-07-22; private origin `main` = `refactor/complete` |
| `lotgood/photonport-protocol` | `refactor/complete` | `0e67e0e` (matrix tuple `acae6f5`) | pushed 2026-07-22; private origin `main` = `refactor/complete` |

What landed since 2026-07-14, all physically verified over USB on the tested
pair: the session v3 authenticated USB wire (mandatory PSK preface +
per-direction HMAC records), transport-explicit server-hello with single-use
`wifiSessionSeed`, receiver-local cursor sprite, frame-admission tuning
(65→73fps on HEVC), and canonical ProRes 422 Proxy/LT (USB-only,
117–119fps at ~4ms p50 encode, receiver `dropped=0`). The
`wip/broken-refactor-snapshot` branches in all three repos preserve a
non-compiling intermediate worktree for archaeology only — never push or
build them; `ooo/*` branches are orchestrator salvage lanes, also not for
publication.

## Repository split

| Repository | License | Role | State |
|---|---|---|---|
| `lotgood/photonport` (this repo) | GPL-3.0 | Mac sender + preserved historical iOS source | public, active |
| `lotgood/photonport-ios` | MIT | standalone fresh iOS receiver | private; origin `main`/`refactor/complete` at `a56d223` (matrix tuple `cb6e9ac`) |
| `lotgood/photonport-protocol` | MIT | canonical pairing-v2 / session-v3 contract | private; origin `main`/`refactor/complete` at `0e67e0e` (matrix tuple `acae6f5`) |

The standalone iOS receiver is a provenance-cleared reconstruction: 47 shipped
files, byte-verified MIT lineage, 1,267 similarity candidates independently
dispositioned APPROVE (receipts in `photonport-ios/artifacts/provenance/`).
`scripts/release-ios.sh` here is a fail-closed guard against building the
retired GPL target. **Retired 2026-07-22 (owner decision):** the monorepo GPL
receiver's rollback claim was already found false by the static audit
(CR-006), and it speaks the pre-authenticated wire, so it cannot interoperate
with the current tuple at all. The owner explicitly waived the
`wifi_wrong_mac` blocker (requires a second Mac) for this retirement — this is
a recorded waiver, not a passed gate. Closure receipt with every removed
path, git blob, and SHA-256:
`artifacts/cross-repo/ios-retirement-closure.json` (preserving commit
recorded inside; history is untouched).

## Supported matrix (only claim)

M4 Max on macOS 27 + iPad Pro 11-inch (M4) on iPadOS 27, USB primary.
WiFi works via SAS-paired TLS-PSK but USB remains the latency-critical
recommendation. No other combination is claimed or tested.

## Physical evidence — 11/14 scenarios pass

Receipt: `artifacts/cross-repo/physical-availability.json` (observations in
`physical-observations.json`). Recorded pass: usb_display, usb_hdr, usb_120hz,
usb_audio, usb_rotation, usb_input, usb_disconnect, usb_replug, wifi_sas,
wifi_tls, wifi_reconnect.

Remaining `not_run` (human, on-device):

1. `wifi_unpaired` — unpair (Mac session row re-pair button, or remove the
   pairing on the device), attempt Connect, confirm rejection, then re-pair
   via fresh SAS comparison. This blocks Mac public release.
2. `wifi_takeover` — while a WiFi session streams, plug USB and confirm the
   receiver rejects the competing session (`session_busy`). This blocks Mac
   public release.
3. `wifi_wrong_mac` — needs a second Mac; stays `not_run` until one exists.
   It blocked only monorepo iOS-target retirement; that retirement was
   executed 2026-07-22 under an explicit owner waiver (see above). It never
   blocked Mac DMG distribution.

Defects found and fixed during the physical session (all verified live):
cursor-lag implicit CALayer animation (photonport-ios `f648668`), EDR-backend
rotation ignore (`3e21563`), pairing keychain prompt/brick (`a9e1da3`), WiFi
video QoS marking (`3a15305`). Known non-defect: WiFi p95 frame latency
~85 ms from system-level radio behavior (AirDrop/AWDL, scans) — mitigate by
disabling AirDrop/Handoff or using USB; app-level levers are exhausted.

## Remaining release gates (`artifacts/cross-repo/transition-readiness.json`)

The 2026-07-14 full test-suite re-verification was green. `ASC_ISSUER_ID` is now
available with the release credentials; the only remaining release-script
environment acknowledgement is `EXPORT_COMPLIANCE_CONFIRMED=1`, which must
remain unset until the Mac export-classification record exists. Credential
availability is not an Apple approval, export conclusion, signing result,
notarization result, or TestFlight result.

| Gate | Blocker | Who |
|---|---|---|
| `g004` | `wifi_unpaired` and `wifi_takeover` before Mac public release; `wifi_wrong_mac` before monorepo iOS retirement only | device owner |
| `export_review` | independent Mac/iOS export classifications; record the Mac review before setting `EXPORT_COMPLIANCE_CONFIRMED=1` | external reviewer |
| `apple_distribution` | App Store Connect, signing, notarization, Gatekeeper, Sparkle `SUPublicEDKey`, TestFlight, and publication receipts remain external records; `ASC_ISSUER_ID` availability alone satisfies none of them | account holder |

Open decisions: publish timing for the two private repositories — both
siblings' local commits were pushed to their private origins on 2026-07-22,
so the pinned protocol commit `acae6f5` is durable there, but the Mac tree
still cannot be rebuilt from public sources until they are published;
pushing `refactor/complete` here to `origin` and landing it on `main`;
whether to push GitHub Pages/appcast for Mac auto-update before 0.1.0
signing. Note that pushing
`main` here triggers `pages.yml` (site deploy) when its watched paths change —
pushing code alone does not publish the site, but a release event does.

## How to re-verify everything

The matrix fails closed unless every root is a clean checkout of the exact
`--expected-*-commit`, so `sourceTuple` always names the immutable snapshots
that were actually executed and can never be re-pinned after the run. The
later commit that stores regenerated receipts, tooling, or docs is an
evidence-recording commit: it is outside the audited source tuple and is
never claimed as executed. If this working tree carries uncommitted edits,
run against an immutable snapshot instead, e.g.
`git clone --no-local . /tmp/photonport-mac-src` (or a detached
`git worktree`), run `./generate.sh` inside it (the gitignored
`OpenSidecar.xcodeproj` must exist before the product build), pass it as
`--mac-root`, and keep `--output` pointing back into this repo's
`artifacts/cross-repo/`.

```sh
# Full cross-repo matrix: every required argparse input is explicit. These
# values must name the candidate commits; the two digests come from its Mac
# pin. Each root must be a clean checkout of its named commit or the run
# fails closed before doing any work.
MAC_COMMIT="$(git rev-parse HEAD)"
IOS_COMMIT="$(git -C ../photonport-ios rev-parse HEAD)"
PROTOCOL_COMMIT="$(git -C ../photonport-protocol rev-parse HEAD)"
COMPATIBILITY_DIGEST="$(python3 -c 'import json; print(json.load(open("Mac/ProtocolBuildPin.json"))["compatibilityDigest"])')"
NORMATIVE_MANIFEST_DIGEST="$(python3 -c 'import json; print(json.load(open("Mac/ProtocolBuildPin.json"))["normativeManifestDigest"])')"

python3 scripts/run-cross-repo-matrix.py \
  --mac-root . \
  --ios-root ../photonport-ios \
  --protocol-root ../photonport-protocol \
  --expected-mac-commit "$MAC_COMMIT" \
  --expected-ios-commit "$IOS_COMMIT" \
  --expected-protocol-commit "$PROTOCOL_COMMIT" \
  --expected-compatibility-digest "$COMPATIBILITY_DIGEST" \
  --expected-normative-manifest-digest "$NORMATIVE_MANIFEST_DIGEST" \
  --output artifacts/cross-repo/automated-matrix.json

# Physical availability + scenario receipt (redacted, read-only probe)
python3 scripts/capture-supported-device-evidence.py --probe-local \
  --observations artifacts/cross-repo/physical-observations.json \
  --output artifacts/cross-repo/physical-availability.json

# Transition readiness (expected exit 2 while M0 gates remain blocked;
# retirementEligible stays false)
python3 scripts/verify-ios-transition-readiness.py \
  --mac-root . --ios-root ../photonport-ios --protocol-root ../photonport-protocol \
  --g004-automated artifacts/cross-repo/automated-matrix.json \
  --g004-physical artifacts/cross-repo/physical-availability.json \
  --g006-provenance ../photonport-ios/artifacts/provenance/g006-closure.json \
  --rollback-build artifacts/cross-repo/rollback-build.json \
  --template artifacts/cross-repo/transition-template.json \
  --output artifacts/cross-repo/transition-readiness.json
```

Debug-run notes: `./generate.sh` (reads `DEVELOPMENT_TEAM` from `.env`), Mac
log at `/tmp/photonport-mac.log`, device log at the app container's
`Documents/photonport-phone.log` (pull via `devicectl device copy from`).
