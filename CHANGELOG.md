# Changelog

All notable PhotonPort changes will be documented in this file.

## [Unreleased]

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
