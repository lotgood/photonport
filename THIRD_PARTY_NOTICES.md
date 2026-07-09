# Third-Party Notices

PhotonPort is a GPL-3.0-only fork of
[OpenDisplay](https://github.com/peetzweg/opendisplay). The repository's root
`LICENSE` file applies to the combined work and preserves the upstream history.

The following separately licensed components or source material are included.

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
