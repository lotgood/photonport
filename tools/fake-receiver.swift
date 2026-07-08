// Fake OpenDisplay receiver — speaks just enough of the wire protocol to
// stand in for a device: sends hello + pings, consumes video frames,
// reports receive rate. For Mac-side testing only.
//
// Usage: swift fake-receiver.swift [rotate] [profile] [port]
//   rotate   announce a portrait re-hello 20s after connect (and back to
//            landscape at 45s) — exercises the Mac's display rebuild path.
//   profile  which panel to impersonate (default 120hdr):
//              120hdr  iPad Pro 12.9" 2732x2048 @2, 120Hz + EDR — the
//                      full HEVC/HDR negotiation path
//              60sdr   iPad 10th gen 2360x1640 @2, 60Hz SDR — the H.264
//                      default path
//              iphone  iPhone 15 Pro 2556x1179 @3, 120Hz + EDR — scale-3
//                      sizing and phone-shaped virtual display
//              legacy  hello with ONLY pixelsWide/pixelsHigh/scale, like
//                      receivers that predate the capability fields — the
//                      Mac must default to 60fps SDR (PhoneInfo optionals)
//   port     listen port (default 9000) — run several fakes on distinct
//            ports for multi-device sessions.
import Foundation
import Network

struct Profile {
    let wide: Int          // landscape long edge, pixels
    let high: Int
    let scale: Double
    let extras: String     // capability fields, "" for legacy hellos

    func hello(portrait: Bool = false) -> String {
        let w = portrait ? high : wide
        let h = portrait ? wide : high
        return "{\"type\":\"hello\",\"pixelsWide\":\(w),\"pixelsHigh\":\(h),\"scale\":\(scale)\(extras)}"
    }
}

let profiles: [String: Profile] = [
    "120hdr": Profile(wide: 2732, high: 2048, scale: 2,
                      extras: ",\"device\":\"iPad\",\"id\":\"FAKE-120HDR\",\"maxFps\":120,\"hdr\":true"),
    "60sdr":  Profile(wide: 2360, high: 1640, scale: 2,
                      extras: ",\"device\":\"iPad\",\"id\":\"FAKE-60SDR\",\"maxFps\":60,\"hdr\":false"),
    "iphone": Profile(wide: 2556, high: 1179, scale: 3,
                      extras: ",\"device\":\"iPhone\",\"id\":\"FAKE-IPHONE\",\"maxFps\":120,\"hdr\":true"),
    "legacy": Profile(wide: 2732, high: 2048, scale: 2, extras: ""),
]

var simulateRotation = false
var profileName = "120hdr"
var port: UInt16 = 9000
for arg in CommandLine.arguments.dropFirst() {
    if arg == "rotate" {
        simulateRotation = true
    } else if profiles[arg] != nil {
        profileName = arg
    } else if let p = UInt16(arg), p > 0 {
        port = p
    } else {
        FileHandle.standardError.write(Data("unknown arg \"\(arg)\" — profiles: \(profiles.keys.sorted().joined(separator: "|")), \"rotate\", or a port number\n".utf8))
        exit(1)
    }
}
let profile = profiles[profileName]!

let listener = try! NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: port)!)

func frame(_ json: String) -> Data {
    let payload = Data(json.utf8)
    var header = UInt32(payload.count).bigEndian
    var d = Data(bytes: &header, count: 4)
    d.append(payload)
    return d
}

listener.newConnectionHandler = { conn in
    print("connection from \(conn.endpoint)")
    var frames = 0, bytes = 0
    var windowStart = Date()
    conn.start(queue: .global())
    conn.send(content: frame(profile.hello()),
              completion: .contentProcessed { _ in })
    if simulateRotation {
        DispatchQueue.global().asyncAfter(deadline: .now() + 20) {
            print("simulating rotation -> portrait")
            conn.send(content: frame(profile.hello(portrait: true)),
                      completion: .contentProcessed { _ in })
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 45) {
            print("simulating rotation -> landscape")
            conn.send(content: frame(profile.hello()),
                      completion: .contentProcessed { _ in })
        }
    }
    let timer = DispatchSource.makeTimerSource(queue: .global())
    timer.schedule(deadline: .now() + 1, repeating: 2)
    timer.setEventHandler {
        let t = Date().timeIntervalSince1970 * 1000
        conn.send(content: frame("{\"type\":\"ping\",\"t\":\(t)}"),
                  completion: .contentProcessed { _ in })
    }
    timer.resume()
    func readLoop() {
        conn.receive(minimumIncompleteLength: 4, maximumLength: 4) { data, _, _, err in
            guard let data, data.count == 4, err == nil else { print("closed"); timer.cancel(); return }
            let len = Int(UInt32(bigEndian: data.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }))
            guard len > 0, len < 1 << 24 else { print("bad length \(len)"); timer.cancel(); return }
            conn.receive(minimumIncompleteLength: len, maximumLength: len) { payload, _, _, err in
                guard let payload, payload.count == len, err == nil else { print("closed"); timer.cancel(); return }
                frames += 1
                bytes += len
                let el = Date().timeIntervalSince(windowStart)
                if el >= 5 {
                    print(String(format: "recv %.0f frames/s  %.1f Mbit/s",
                                 Double(frames) / el, Double(bytes) * 8 / el / 1_000_000))
                    frames = 0; bytes = 0; windowStart = Date()
                }
                readLoop()
            }
        }
    }
    readLoop()
}
listener.start(queue: .global())
print("fake receiver [\(profileName)] listening on \(port)")
RunLoop.main.run()
