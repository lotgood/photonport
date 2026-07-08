// SPDX-License-Identifier: GPL-3.0-only
// Part of PhotonPort, a GPL-3.0 fork of OpenDisplay
// (https://github.com/peetzweg/opendisplay, (c) peetzweg and contributors).
// This file (c) 2026 hyupji, added in the fork.

// CapabilityProbe — startup checks for the private/OS-gated surfaces this
// app stands on. Each of them degrades SILENTLY inside the pipeline
// (runtime selector checks, fallback chains) — right for the stream, wrong
// for the human debugging "why is it suddenly SDR after the macOS update?".
// So: probe once at launch, log once, and surface misses in the control
// window. All lookups go through the ObjC runtime, never through direct
// class references, so probing is safe even when the API is gone (the
// private classes are weak-linked — see CGVirtualDisplayPrivate.h).
import Foundation

enum CapabilityProbe {
    /// The private CGVirtualDisplay class cluster is present. False means a
    /// macOS update removed or renamed it — extend mode cannot work at all
    /// (mirror mode is unaffected; it captures the real display).
    static let virtualDisplayAPI: Bool =
        ["CGVirtualDisplay", "CGVirtualDisplayDescriptor",
         "CGVirtualDisplaySettings", "CGVirtualDisplayMode"]
            .allSatisfy { NSClassFromString($0) != nil }

    /// The EDR mode initializer (transferFunction:) exists — required for
    /// HDR compositing headroom on the virtual display.
    static let edrVirtualDisplay: Bool = {
        guard let mode = NSClassFromString("CGVirtualDisplayMode") as? NSObject.Type
        else { return false }
        return mode.instancesRespond(to: NSSelectorFromString(
            "initWithWidth:height:refreshRate:transferFunction:"))
    }()

    /// CoreAudio process taps (mute-while-forwarding audio), macOS 14.2+.
    static let audioTapAPI: Bool = {
        if #available(macOS 14.2, *) { return true }
        return false
    }()

    /// True when every probe passed — the control window hides its
    /// Compatibility section then (loud failure, silent success).
    static var allGood: Bool { virtualDisplayAPI && edrVirtualDisplay && audioTapAPI }

    static func logSummary() {
        Log.info("capabilities: virtualDisplayAPI=\(virtualDisplayAPI) "
                 + "edrVirtualDisplay=\(edrVirtualDisplay) audioTapAPI=\(audioTapAPI)")
    }
}
