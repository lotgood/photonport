# Third-Party Notices

This repository remains a **GPL-3.0-only Mac sender and historical source
repository**. The root `LICENSE` applies to this repository's combined work and
preserves the OpenDisplay history. The standalone
[photonport-ios](https://github.com/lotgood/photonport-ios) receiver and
[photonport-protocol](https://github.com/lotgood/photonport-protocol) contract
are separate MIT-licensed repositories; those links do not relicense or alter
the old GPL-licensed iOS history retained here.

The following separately licensed components or source material are included in
this repository.

## CGVirtualDisplay private interface declarations

- Source: [KhaosT/CGVirtualDisplay](https://github.com/KhaosT/CGVirtualDisplay)
- File: `Mac/CGVirtualDisplayPrivate.h`
- License: Apache License 2.0
- License text: `LICENSES/Apache-2.0.txt`

The local header includes compatibility additions recorded in PhotonPort's git
history. The underlying CoreGraphics implementation is supplied by macOS and is
not redistributed by this project.

## Sparkle 2.9.4

- Source: [sparkle-project/Sparkle](https://github.com/sparkle-project/Sparkle)
- Use: macOS update framework and release tooling
- License and bundled external-component notices: `LICENSES/Sparkle.txt`

Release packages must ship this file and the `LICENSES` directory alongside
PhotonPort's root `LICENSE` file.
