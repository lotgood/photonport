import Foundation

/// Logs to NSLog (visible via `log stream` / simctl) and to a file in the
/// app's Documents directory (readable via `simctl get_app_container data`).
enum Log {
    private static let queue = DispatchQueue(label: "log")
    private static let maxBytes: UInt64 = 1_000_000
    private static let fileURL: URL = {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("photonport-phone.log")
    }()
    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()
    private static var previousFileURL: URL {
        fileURL.deletingPathExtension().appendingPathExtension("previous.log")
    }

    static func info(_ message: String) {
        NSLog("[opensidecar] %@", message)
        let line = "[\(formatter.string(from: Date()))] \(message)\n"
        queue.async {
            rotateIfNeeded()
            guard let data = line.data(using: .utf8) else { return }
            if let handle = try? FileHandle(forWritingTo: fileURL) {
                handle.seekToEndOfFile()
                handle.write(data)
                try? handle.close()
            } else {
                try? line.write(to: fileURL, atomically: true, encoding: .utf8)
            }
        }
    }

    private static func rotateIfNeeded() {
        let fm = FileManager.default
        guard let values = try? fileURL.resourceValues(forKeys: [.fileSizeKey]),
              UInt64(values.fileSize ?? 0) >= maxBytes else { return }
        try? fm.removeItem(at: previousFileURL)
        try? fm.moveItem(at: fileURL, to: previousFileURL)
    }
}
