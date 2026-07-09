# PhotonPort

> ⚠️ **EXPERIMENTAL — UNSUPPORTED — USE AT YOUR OWN RISK.**
> This is a personal research fork, tested on exactly **one** hardware pair:
> an Apple-Silicon Mac (M4 Max, macOS 26) and an iPad Pro 11" (M4, iOS 26)
> over USB. Every number below was measured on that setup and **nowhere
> else**. Fallback paths for other devices/OS versions exist in code but are
> unverified. No binaries, no support guarantee, no roadmap promises.

Turns an iPad or iPhone into a high-refresh, wide-dynamic-range external
display for a Mac over a USB cable, with system audio routed to the device
(the Mac mutes while forwarding, like Sidecar).

PhotonPort is a fork of [OpenDisplay](https://github.com/peetzweg/opendisplay)
by [@peetzweg](https://github.com/peetzweg) (GPL-3.0). The connection
plumbing (usbmuxd dial, Bonjour discovery, touch injection, receiver
scaffolding) is upstream's work; this fork adds the pipeline described below.
General-purpose bug fixes are proposed upstream where they fit; the
experimental display/audio work stays here.

## Security — read this first

- **WiFi requires pairing and runs over TLS.** Pairing is a one-time
  **SAS numeric comparison** (Bluetooth-style): both devices derive the same
  6-digit code from a fresh X25519 key exchange and you confirm the two
  screens match. No secret is typed or transmitted, so there is no offline
  PIN oracle, and an active same-network attacker inserting a fake endpoint
  produces *different* codes on the two screens — mismatch means "don't
  confirm". The confirmed key is stored per-Mac (device-only Keychain) and
  WiFi sessions run over TLS-PSK. The receiver's plaintext port only accepts
  loopback (USB/usbmux) peers, and the pairing listener exists only while the
  device's pairing screen is open.
- **Residual WiFi caveats** (documented, not yet fixed): TLS-PSK has no
  forward secrecy (a leaked long-term key can decrypt past recorded
  sessions); a holder of a valid/stolen PSK can take over an active session
  (no per-session binding yet). Prefer USB for anything sensitive. The
  `-host`/`-port` manual endpoint stays plaintext — use it only for
  loopback-style tunnels.
- The Mac app requires Screen Recording (and, for audio, System Audio
  Recording) permission — it captures your screen and system audio and sends
  them to your device. Nothing else; no servers, no analytics, no accounts.

## What was observed on the tested setup (USB)

| | Apple Sidecar | PhotonPort (tested pair) |
|---|---|---|
| Resolution | fixed scale | native 2816×2048 |
| Refresh | 60Hz | 120Hz (118fps delivered) |
| Dynamic range | SDR | HDR — EDR compositing, HLG 10-bit |
| Video latency | ~30ms | 5–6ms e2e p50 |
| Audio | routed to device | routed, ~30ms, dedicated TCP socket |
| Codec | private | ProRes 422 Proxy/LT (opt-in) or HEVC / H.264 |

## How it works (technical notes)

- **EDR virtual display** — `CGVirtualDisplay` (the same private API every
  virtual-display product uses) exposes a newer mode initializer with a
  `transferFunction` parameter on recent macOS; value 1 was observed to make
  WindowServer composite the display with real HDR headroom. Guarded by a
  runtime selector check with an SDR fallback chain.
- **CGDisplayStream capture for HDR** — ScreenCaptureKit tone-maps virtual
  displays to SDR even with its macOS 15 HDR presets (measured with an EDR
  test pattern). The legacy CGDisplayStream delivers the float16 EDR
  composite unclipped, so the HDR path rides it.
- **Reference-pinned HLG** — a Metal pass converts float16 extended-sRGB to
  BT.2408 HLG (SDR white = 203 nits) before encoding; VideoToolbox's own
  mapping over-brightened highlights on a high-headroom panel.
- **ProRes over the wire (opt-in, USB only)** — intra-only ProRes 422 on the
  media engine's dedicated block bypasses the HEVC engine's throughput
  ceiling (~430Mpx/s measured): native 120fps at ~4ms encode, ~330Mbps on a
  measured ~1Gbps usbmux link.
- **Audio tap routing** — a CoreAudio process tap (`mutedWhenTapped`,
  macOS 14.2+) mutes the Mac and forwards 5.3ms PCM buffers on a dedicated
  connection (its own TCP socket on USB, its own TLS connection over WiFi)
  so audio never queues behind video frames. If the Mac's default output is
  Bluetooth headphones, forwarding pauses and audio stays on the headphones.
- **WiFi transport (pairing + TLS, transport-tuned)** — WiFi runs over
  TLS-PSK after a one-time SAS-numeric-comparison pairing (see Security). It can't carry the
  USB-tier native-120fps HDR config — the HEVC encoder needs ~20ms/frame at
  native res (ProRes isn't available off USB) and the radio's usable
  bitrate is a fraction of usbmux — so WiFi is capped to 60fps and a
  reduced capture scale, with a hard encoder burst cap (DataRateLimits) and
  a deeper audio jitter buffer. Measured on the tested pair (−64dBm 5GHz):
  ~20ms e2e p50, stable ~113ms audio. TCP still head-of-line-stalls on
  radio packet loss, so occasional brief hitches remain — USB avoids them.
- Fixes worth noting for upstream: H.264 silently rejects every frame above
  its level-5.2 pixel-rate ceiling (VideoToolbox returns noErr + nil buffer);
  backpressure drops must not force IDRs; a saturated encoder needs an
  in-flight gate or it queues frames as pure latency.

## Known limitations / non-goals

- **Unverified**: anything that is not the tested pair — Intel Macs,
  macOS 14/15 fallbacks, 60Hz/SDR devices, iPhone receivers, WiFi on other
  networks/APs, multi-device sessions, HDR color accuracy beyond "highlights
  visibly render". (WiFi was measured on the tested pair only.)
- **Private API**: the virtual display (and its EDR mode) can break on any
  macOS update, and the Mac app can never ship in the Mac App Store.
- **WiFi**: paired + TLS and transport-tuned (60fps + reduced resolution,
  its own audio TLS connection, conservative bitrates), but a lossy radio
  still causes occasional brief hitches TCP can't hide. Older
  senders/receivers can't talk to this fork over WiFi anymore (plaintext is
  rejected; pairing required).
- Out of scope: Windows/Android, audio input (mic) forwarding.

## Toggles (`defaults write dev.hyupji.photonport.mac.debug …`)

- `prores proxy|lt` — ProRes wired mode (ignored off USB)
- `hdr -bool NO` / `audiotap -bool NO` / `audio -bool NO` — feature opt-outs
- `diag -bool true` / `blast -bool true` / `testPattern -bool true` —
  pipeline diagnosis, wire-throughput test, animated load generator

## Building

Requirements: an Apple-Silicon or Intel Mac supported by Xcode, Xcode 26 or
newer, and XcodeGen 2.45.4. The macOS target deploys to macOS 14.0+; the iOS
target deploys to iOS/iPadOS 17.0+. Runtime compatibility outside the tested
hardware/OS pair remains unverified.

```
echo "DEVELOPMENT_TEAM=YOURTEAMID" > .env   # see .env.example
./generate.sh
./scripts/test-pairing-vectors.sh
xcodebuild -project OpenSidecar.xcodeproj -scheme OpenSidecarMac -configuration Debug -derivedDataPath build build
xcodebuild -project OpenSidecar.xcodeproj -scheme OpenSidecariOS -configuration Debug -destination 'platform=iOS,id=<device>' -derivedDataPath build -allowProvisioningUpdates build
```

Internal type/scheme names keep upstream's `OpenSidecar` prefix on purpose —
smaller diff against upstream, easier future merges.

## License

GPL-3.0, same as upstream — see [LICENSE](LICENSE). Original work
© peetzweg and contributors; modifications © 2026 hyupji (fork started
2026-07-08; per-change notices live in the git history). If you distribute
binaries built from this tree, GPL-3.0 requires you to provide the exact
corresponding source.

See [Third-Party Notices](THIRD_PARTY_NOTICES.md),
[asset licensing](ASSETS.md), [Security Policy](SECURITY.md),
[Privacy Policy](PRIVACY.md), and [Contributing](CONTRIBUTING.md).
