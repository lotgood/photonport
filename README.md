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

- **WiFi requires pairing and runs over TLS.** A one-time 6-digit PIN
  exchange (X25519 ECDH with a PIN-bound HMAC proof — simplified Bluetooth
  numeric-entry pairing) establishes a per-Mac key; WiFi sessions then run
  over TLS-PSK. The receiver's plaintext port only accepts loopback
  (USB/usbmux) peers, and the pairing listener exists only while the
  device's pairing screen is open. Residual risks: an active MITM during
  the pairing moment gets exactly one online PIN guess (a failed attempt
  regenerates the PIN); a recorded pairing handshake allows offline PIN
  cracking, but the PIN is single-use and the session key never derives
  from it. The `-host`/`-port` manual endpoint stays plaintext — use it
  only for loopback-style tunnels.
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
  TCP connection so audio never queues behind video frames. If the Mac's
  default output is Bluetooth headphones, forwarding pauses and audio stays
  on the headphones.
- Fixes worth noting for upstream: H.264 silently rejects every frame above
  its level-5.2 pixel-rate ceiling (VideoToolbox returns noErr + nil buffer);
  backpressure drops must not force IDRs; a saturated encoder needs an
  in-flight gate or it queues frames as pure latency.

## Known limitations / non-goals

- **Unverified**: anything that is not the tested pair — Intel Macs,
  macOS 14/15 fallbacks, 60Hz/SDR devices, iPhone receivers, WiFi
  performance, multi-device sessions, HDR color accuracy beyond "highlights
  visibly render".
- **Private API**: the virtual display (and its EDR mode) can break on any
  macOS update, and the Mac app can never ship in the Mac App Store.
- **WiFi**: paired + TLS, but still sized conservatively — the dedicated
  audio socket and the raised bitrates are USB-only; WiFi sessions use the
  legacy bitrates and the shared socket. Older senders/receivers cannot
  talk to this fork over WiFi anymore (plaintext is rejected).
- Out of scope: Windows/Android, audio input (mic) forwarding.

## Toggles (`defaults write dev.hyupji.photonport.mac.debug …`)

- `prores proxy|lt` — ProRes wired mode (ignored off USB)
- `hdr -bool NO` / `audiotap -bool NO` / `audio -bool NO` — feature opt-outs
- `diag -bool true` / `blast -bool true` / `testPattern -bool true` —
  pipeline diagnosis, wire-throughput test, animated load generator

## Building

```
echo "DEVELOPMENT_TEAM=YOURTEAMID" > .env   # see .env.example
./generate.sh
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
