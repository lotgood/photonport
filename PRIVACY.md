# PhotonPort Privacy Policy

Effective date: 2026-07-10

PhotonPort does not provide an account system, analytics service, advertising,
or developer-operated relay server. Display video, system audio, input events,
and pairing messages travel directly between the Mac and the user's iPhone or
iPad over USB/usbmux or the local network.
The Mac sender remains in this GPL-3.0-only repository. The transitioned iOS
receiver is documented and built separately at
[lotgood/photonport-ios](https://github.com/lotgood/photonport-ios), and the
MIT-licensed protocol is at
[lotgood/photonport-protocol](https://github.com/lotgood/photonport-protocol).
This policy does not imply that the historical monorepo iOS code was relicensed.
The only supported device pair is an M4 Max Mac on macOS 27 over USB with
an iPad Pro 11-inch M4 on iPadOS 27; other OS versions remain unverified.
## Data processed

- The Mac app processes screen pixels, system audio, cursor state, and display
  configuration to provide streaming.
- The iOS app processes the received media and sends touch/scroll control
  events to the connected Mac.
- Pairing creates local installation identifiers and cryptographic keys. Keys
  are stored in the platform Keychain; names and local settings are stored in
  UserDefaults.
- Diagnostic logs are stored locally. They may contain hardware/OS details,
  shortened device identifiers, device or Bonjour names, and network error
  details. Logs rotate at approximately 1 MB and are not uploaded automatically.

## Network services

WiFi streaming and pairing use the local network. The macOS app may contact
GitHub Pages and GitHub Releases to check for and download signed updates.
GitHub may process connection metadata under its own privacy terms. TestFlight
and App Store distribution are operated by Apple and may provide Apple and the
developer with crash and testing metrics under Apple's terms.

## Collection, sharing, and retention

The PhotonPort developer does not automatically collect or sell app data. Data
stays on the participating devices unless the user deliberately shares a log or
diagnostic report. Local app data remains until removed by the user, app reset,
or app deletion; rotated logs replace the previous log after the next rotation.

Before posting a public issue, redact device names, identifiers, IP addresses,
Bonjour names, and any personal content.

## Contact

Use the repository's GitHub Issues for general privacy questions. For a report
that includes sensitive security or personal information, use GitHub private
vulnerability reporting instead of a public issue:

<https://github.com/lotgood/photonport/security/advisories/new>
