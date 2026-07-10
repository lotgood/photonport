# Changelog

All notable PhotonPort changes will be documented in this file.

## [Unreleased]

### Changed

- Retargeted the sole supported physical pair to the currently verified
  hardware: M4 Max on macOS 27 + iPad Pro 11-inch (M4) on iPadOS 27 over USB.
- Standalone-repository split: the iOS receiver moved to the MIT
  `photonport-ios` repository (canonical protocol contract lives in MIT
  `photonport-protocol`); `scripts/release-ios.sh` is now a fail-closed
  transition guard. This monorepo keeps the historical GPL iOS source and the
  Mac sender.

### Fixed

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

### Added

- Cross-repository verification tooling and receipts: compatibility manifest
  checks, automated matrix runner, supported-device evidence capture with
  literal physical-scenario observations (11/14 recorded pass), iOS transition
  readiness verifier, provenance audit/scan/baseline tools, and a Mac protocol
  adversarial harness.

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
