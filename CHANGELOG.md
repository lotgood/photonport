# Changelog

All notable PhotonPort changes will be documented in this file. PhotonPort has
not published a signed binary release yet.

## [Unreleased]

### Added

- Public macOS sender and iOS receiver source for the PhotonPort fork.
- Deterministic Mac/iOS pairing-vector parity test.
- iOS privacy manifest and a public privacy-policy page.
- macOS notarization, Sparkle appcast signing, and iOS archive release scripts.
- GitHub Actions builds for macOS and iOS, full-history secret scanning, and
  GitHub Pages deployment.

### Changed

- Redacted device identifiers and network details from diagnostic logs.
- Added bounded log rotation and release-time signing, export-compliance, and
  distribution-policy gates.
- Namespaced PhotonPort release tags as `photonport-v<version>`.

## Upstream provenance

PhotonPort is derived from [OpenDisplay](https://github.com/peetzweg/opendisplay)
under GPL-3.0. Consult the upstream repository for changes made before the
PhotonPort fork.
