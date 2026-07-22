# Changelog

All notable PhotonPort changes will be documented in this file.

## [Unreleased]

### Added

- Authenticated USB transport: a mandatory PSK-bound preface (usb-bind
  handshake) plus per-direction HMAC-tagged records for every session,
  control, video, and audio payload. USB is no longer trusted by locality.
- Canonical ProRes 422 over the wire (`prores proxy|lt`, USB only): intra-only
  frames on the media engine's dedicated ProRes block deliver native
  2816×1940 at 117–119fps with ~4ms p50 encode latency and zero receiver-side
  drops on the tested pair.
- Transport-explicit session v3 server-hello with a fresh single-use
  `wifiSessionSeed` on Wi-Fi; the legacy USB session seed is gone.
- Cross-repository verification tooling and receipts: compatibility manifest
  checks, automated matrix runner, supported-device evidence capture with
  literal physical-scenario observations (11/14 recorded pass), iOS transition
  readiness verifier, provenance audit/scan/baseline tools, and a Mac protocol
  adversarial harness.

### Removed

- The preserved GPL-3.0 monorepo iOS receiver (`iOS/` sources and the
  `OpenSidecariOS` target) is retired from the working tree by owner
  decision. It spoke the pre-authenticated wire and could not interoperate
  with the current protocol; the standalone MIT receiver is the only
  supported one. Full history is preserved; the machine-readable closure
  receipt (every removed path with git blob and SHA-256, plus the preserving
  commit) lives at `artifacts/cross-repo/ios-retirement-closure.json`.

### Changed

- Frame admission recovers rate lost to over-strict gating: encoder pipeline
  shed threshold at depth 3 and a half-interval pacing floor
  (65 → ~73fps on the HEVC Main10 HLG path, which measures ~30ms/frame p50
  on macOS 27).
- The receiver renders the pointer sprite locally; the wire carries only
  normalized cursor position and visibility.
- Retargeted the sole supported physical pair to the currently verified
  hardware: M4 Max on macOS 27 + iPad Pro 11-inch (M4) on iPadOS 27 over USB.
- Standalone-repository split: the iOS receiver moved to the MIT
  `photonport-ios` repository (canonical protocol contract lives in MIT
  `photonport-protocol`); `scripts/release-ios.sh` is now a fail-closed
  transition guard. This monorepo keeps the historical GPL iOS source and the
  Mac sender.

### Fixed

- usbmuxd Listen events (tag 0) no longer kill the device watcher, the event
  stream reads without a request deadline, and ListDevices accepts the
  daemon's actual reply shape.
- VideoToolbox tuning properties rejected by the hardware (e.g.
  `MaxFrameDelayCount` under low-latency rate control) no longer abort
  encoder configuration; only wire-contract properties fail closed.

- Rotation on the CGDisplayStream-EDR capture backend: mid-session hellos were
  silently ignored because the reconfigure guard only checked the
  ScreenCaptureKit stream. Verified live in both orientations over USB and
  WiFi.
- Pairing keychain access: PSK reads are non-interactive (a foreign-signature
  item can no longer pop a keychain prompt that dismisses the menu-bar
  popover), and an un-updatable stale item is replaced instead of bricking
  re-pairing.
- WiFi video connection now carries the `interactiveVideo` service class;
  unmarked best-effort traffic previously ate radio contention as p95
  frame-latency spikes (measured rtt spikes 87–182 ms settled to 8–15 ms).

## [0.1.0] - 2026-07-10

### Added

- Public macOS sender and iOS receiver source for the PhotonPort fork.
- Deterministic Mac/iOS pairing-vector parity test.
- Receiver-first protocol-v3 proofs with receiver-wide primary ownership,
  accept-before-capture sequencing, audio-channel binding, and replay rejection.
- Deterministic Mac/iOS session-ownership harness in CI.
- iOS privacy manifest and a public privacy-policy page.
- macOS notarization, Sparkle appcast signing, and iOS archive release scripts.
- GitHub Actions builds for macOS and iOS, full-history secret scanning, and
  GitHub Pages deployment.
- Pages appcast selection that preserves the latest namespaced PhotonPort feed
  across privacy pushes and unrelated release events, with fail-closed dispatch.

### Changed

- Redacted device identifiers and network details from diagnostic logs.
- Added bounded log rotation and release-time signing, export-compliance, and
  distribution-policy gates.
- Namespaced PhotonPort release tags as `photonport-v<version>`.
- Split the Mac+iOS export-classification gate from the TestFlight-only
  GPL/Apple distribution-terms gate.

## Upstream provenance

PhotonPort is derived from [OpenDisplay](https://github.com/peetzweg/opendisplay)
under GPL-3.0. Consult the upstream repository for changes made before the
PhotonPort fork.
