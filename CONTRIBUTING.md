# Contributing

PhotonPort is an experimental GPL-3.0-only fork tested on a very small hardware
matrix. Small, evidence-backed changes are preferred.

## Before opening a pull request

1. Install Xcode 26 or newer and XcodeGen 2.45.4.
2. Copy `.env.example` to `.env` and set your own Apple development team when a
   signed device build is needed. Never commit signing credentials.
3. Run `./generate.sh`.
4. Run `./scripts/test-pairing-vectors.sh`.
5. Build both unsigned targets using the commands in `README.md`.
6. Explain the tested Mac/device/OS/transport matrix in the pull request.

Do not include generated `OpenSidecar.xcodeproj`, build products, archives,
provisioning profiles, device identifiers, IP addresses, or unredacted logs.

By submitting a contribution, you agree that it is licensed under
GPL-3.0-only. Files derived from a separately licensed source must preserve the
source, copyright, and license notice.
