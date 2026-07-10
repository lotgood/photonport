# PhotonPort handoff — state and remaining gates

Last updated: 2026-07-11 (after the first full physical test session on the
supported pair). This file is the single entry point for picking the release
work back up. Machine-readable receipts live under `artifacts/`; durable goal
state lives in `.gjc/ultragoal/` (local, not committed).

## Repository split

| Repository | License | Role | State |
|---|---|---|---|
| `lotgood/photonport` (this repo) | GPL-3.0 | Mac sender + preserved historical iOS source | public, active |
| `lotgood/photonport-ios` | MIT | standalone fresh iOS receiver | private, pushed (`f648668`) |
| `lotgood/photonport-protocol` | MIT | canonical pairing-v2 / session-v3 contract | private, pushed (`c23d345`) |

The standalone iOS receiver is a provenance-cleared reconstruction: 47 shipped
files, byte-verified MIT lineage, 1,267 similarity candidates independently
dispositioned APPROVE (receipts in `photonport-ios/artifacts/provenance/`).
`scripts/release-ios.sh` here is a fail-closed transition guard; the monorepo
iOS target stays as rollback until `retirementReady` flips true.

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
   via fresh SAS comparison.
2. `wifi_takeover` — while a WiFi session streams, plug USB and confirm the
   receiver rejects the competing session (`session_busy`).
3. `wifi_wrong_mac` — needs a second Mac; stays `not_run` until one exists.

Defects found and fixed during the physical session (all verified live):
cursor-lag implicit CALayer animation (photonport-ios `f648668`), EDR-backend
rotation ignore (`3e21563`), pairing keychain prompt/brick (`a9e1da3`), WiFi
video QoS marking (`3a15305`). Known non-defect: WiFi p95 frame latency
~85 ms from system-level radio behavior (AirDrop/AWDL, scans) — mitigate by
disabling AirDrop/Handoff or using USB; app-level levers are exhausted.

## Remaining release gates (`artifacts/cross-repo/transition-readiness.json`)

| Gate | Blocker | Who |
|---|---|---|
| `g004` | 3 physical scenarios above | device owner |
| `export_review` | independent Mac/iOS export classifications (`Distribution/EXPORT_CLASSIFICATION.json` in photonport-ios; Mac gate in `scripts/release-mac.sh`) | external reviewer |
| `apple_distribution` | `ASC_ISSUER_ID` missing; App Store Connect record, signing, notarization, Gatekeeper, Sparkle `SUPublicEDKey` swap, TestFlight, publication receipts | account holder |

Open decisions: publish timing for the two private repositories; whether to
push GitHub Pages/appcast for Mac auto-update before 0.1.0 signing.

## How to re-verify everything

```sh
# Full cross-repo matrix (tests, builds, gates, compatibility receipt) — 11 commands
python3 scripts/run-cross-repo-matrix.py

# Physical availability + scenario receipt (redacted, read-only probe)
python3 scripts/capture-supported-device-evidence.py --probe-local \
  --observations artifacts/cross-repo/physical-observations.json \
  --output artifacts/cross-repo/physical-availability.json

# Transition readiness (retirementReady flips true when every gate passes)
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
