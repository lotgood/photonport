import AppKit
import XCTest

final class OpenSidecarMacAuditSmokeTests: XCTestCase {
    func testHostApplicationLoads() {
        XCTAssertNotNil(NSApplication.shared)
    }
}
