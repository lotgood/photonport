# Security policy

PhotonPort captures a Mac display and system audio, accepts input events from a
paired device, and exposes local-network listeners. Please do not publish a
suspected vulnerability, pairing transcript, device identifier, IP address, or
unredacted log in a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting form:

<https://github.com/lotgood/photonport/security/advisories/new>

Include affected commit/version, transport (USB or WiFi), OS/device versions,
reproduction steps, and the security impact. Redact secrets and personal data.
You should receive an acknowledgement within seven days. This is an
experimental, unsupported project, so no remediation SLA is promised.

## Supported versions

Only the latest commit on `main` and the latest published PhotonPort release are
considered for security fixes. Upstream OpenDisplay issues should be reported to
the upstream project unless they also affect PhotonPort-specific code.
The standalone iOS receiver and protocol repositories are separate MIT-licensed
projects: [photonport-ios](https://github.com/lotgood/photonport-ios) and
[photonport-protocol](https://github.com/lotgood/photonport-protocol). This
repository remains GPL-3.0-only for the Mac sender and retained history; the
split does not relicense historical iOS code here.

The compatibility manifest is protocol 3.0.0, pairing 2.0.0, Mac minimum 0.1.0,
and iOS minimum 1.0.0, with mismatches failing closed. The only supported
pair is an M4 Max Mac on macOS 27 over USB with an iPad Pro 11-inch M4 on
iPadOS 27. Other OS versions are unverified.
## Current security boundaries

- WiFi requires human-confirmed SAS pairing, then uses TLS-PSK plus receiver-first
  protocol-v3 proofs that bind the primary and audio connections to one active
  receiver session.
- The receiver permits one active primary across all paired identities. Same- or
  cross-identity replacement is rejected until explicit disconnect, connection
  loss, or the 5-second liveness timeout.
- USB/usbmux traffic is plaintext, accepted only from structural loopback peers,
  and uses a fresh per-connection session seed for the v3 proof.
  The seed binds one primary connection and its channels; it does not authenticate
  a human or paired Mac identity against a locally compromised device. The UI
  therefore labels such sessions generically as “USB Mac.”
- The manual host/port endpoint is plaintext and is intended only for trusted
  loopback-style tunnels.
- TLS-PSK has no forward secrecy. A valid or stolen PSK may claim an idle receiver
  first (causing a temporary lockout) or impersonate a receiver to the Mac; session
  binding prevents silent takeover of an already active receiver but does not
  provide key revocation or PFS. Prefer USB for sensitive use.
