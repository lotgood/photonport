# PhotonPort

Turn an iPad or iPhone into a **120Hz, true-HDR, ProRes-grade** external
display for your Mac — over a USB cable, at single-digit-millisecond latency,
with system audio routed to the device (Sidecar-style: the Mac mutes while
forwarding).

PhotonPort is a fork of [OpenDisplay](https://github.com/peetzweg/opendisplay)
by [@peetzweg](https://github.com/peetzweg) (GPL-3.0). The connection
plumbing (usbmuxd dial, Bonjour discovery, touch injection, receiver
scaffolding) is his; everything below is what this fork adds on top.
This is a personal build tuned for exactly one hardware pair — an
Apple-Silicon Mac on macOS 26 and an M4 iPad Pro — with fallbacks kept
but unverified elsewhere.

## What it does (all measured, USB, M4 Max → iPad Pro 11" M4)

| | Apple Sidecar | PhotonPort |
|---|---|---|
| Resolution | fixed scale | native 2816×2048 |
| Refresh | 60Hz | **120Hz** (118fps delivered) |
| Dynamic range | SDR | **true HDR** (EDR, HLG 10-bit) |
| Video latency | ~30ms | **5–6ms e2e p50** |
| Audio | routed to device | routed to device, ~30ms, own TCP socket |
| Codec | private | ProRes 422 Proxy/LT (opt-in) or HEVC |

## How (the interesting parts)

- **EDR virtual display** — the macOS 26 private
  `CGVirtualDisplayMode initWithWidth:height:refreshRate:transferFunction:`
  initializer with `transferFunction: 1` makes WindowServer composite the
  virtual display with real HDR headroom (`potentialEDR 5.0`). Probed
  empirically; value 1 is the only one that works.
- **CGDisplayStream capture for HDR** — ScreenCaptureKit tone-maps virtual
  displays to SDR even with its macOS 15 HDR presets (measured: an EDR 4×
  test pattern captured pinned at SDR white). The legacy CGDisplayStream
  delivers the float16 EDR composite unclipped, so the HDR path rides it.
- **Reference-pinned HLG** — a Metal pass converts float16 extended-sRGB to
  BT.2408 HLG (SDR white = 203 nits) before encoding; letting VideoToolbox
  pick its own mapping blew highlights out on a 16×-headroom panel.
- **ProRes over the wire** — opt-in intra-only ProRes 422 on the media
  engine's dedicated block bypasses the HEVC engine's ~430Mpx/s ceiling:
  native 120fps at 4ms encode, ~330Mbps on a measured ~1Gbps usbmux link.
- **Audio tap routing** — a CoreAudio process tap (`mutedWhenTapped`) mutes
  the Mac and forwards 5.3ms PCM buffers on a dedicated TCP connection
  (audio never queues behind in-flight video frames).
- Upstream fixes worth cherry-picking: H.264 silently rejects every frame
  above its level-5.2 pixel-rate ceiling (native@120 = black screen);
  backpressure drops must not force IDRs; a saturated encoder needs an
  in-flight gate or it queues ~5 frames of pure latency.

## Toggles (personal-build style, `defaults write dev.hyupji.photonport.mac.debug …`)

- `prores proxy|lt` — ProRes wired mode (needs the bandwidth of a cable)
- `hdr -bool NO` / `audiotap -bool NO` / `audio -bool NO` — feature opt-outs
- `diag -bool true` / `blast -bool true` / `testPattern -bool true` — pipeline
  diagnosis, wire-throughput test, animated load generator

## Building

```
echo "DEVELOPMENT_TEAM=YOURTEAMID" > .env
./generate.sh
xcodebuild -project OpenSidecar.xcodeproj -scheme OpenSidecarMac -configuration Debug -derivedDataPath build build
xcodebuild -project OpenSidecar.xcodeproj -scheme OpenSidecariOS -configuration Debug -destination 'platform=iOS,id=<device>' -derivedDataPath build -allowProvisioningUpdates build
```

Internal type/scheme names still carry upstream's `OpenSidecar` prefix on
purpose — smaller diff against upstream, easier future merges.

## License

GPL-3.0, same as upstream. Original work © peetzweg and contributors;
modifications © 2026 hyupji. Prominent-change notices live in the git
history (`turbo` branch onward).
