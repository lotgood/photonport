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

## Current security boundaries

- WiFi requires human-confirmed SAS pairing and then uses TLS-PSK.
- USB/usbmux traffic is plaintext and is accepted only from loopback peers.
- The manual host/port endpoint is plaintext and is intended only for trusted
  loopback-style tunnels.
- TLS-PSK currently has no forward secrecy or active-session binding. These are
  documented residual risks, not claims of complete transport security.
