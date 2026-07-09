import Foundation

/// Appends timestamped lines to /tmp/photonport-mac.log (and stdout) so the
/// stream can be debugged without a debugger attached.
enum Log {
    private static let path = "/tmp/photonport-mac.log"
    private static let previousPath = "/tmp/photonport-mac.previous.log"
    private static let maxBytes: UInt64 = 1_000_000
    private static let queue = DispatchQueue(label: "log")
    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    static func info(_ message: String) {
        let line = "[\(formatter.string(from: Date()))] \(message)\n"
        print(line, terminator: "")
        queue.async {
            rotateIfNeeded()
            guard let data = line.data(using: .utf8) else { return }
            if let handle = FileHandle(forWritingAtPath: path) {
                handle.seekToEndOfFile()
                handle.write(data)
                try? handle.close()
            } else {
                try? line.write(toFile: path, atomically: true, encoding: .utf8)
            }
        }
    }

    private static func rotateIfNeeded() {
        let fm = FileManager.default
        guard let size = (try? fm.attributesOfItem(atPath: path)[.size]) as? NSNumber,
              size.uint64Value >= maxBytes else { return }
        try? fm.removeItem(atPath: previousPath)
        try? fm.moveItem(atPath: path, toPath: previousPath)
    }
}
