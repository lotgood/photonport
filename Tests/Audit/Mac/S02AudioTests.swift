import AudioToolbox
import XCTest
@testable import PhotonPort

final class S02AudioTests: XCTestCase {
    func testTapRejectsUnsupportedFormats() {
        var invalid = AudioStreamBasicDescription()
        invalid.mSampleRate = 48_000
        invalid.mBitsPerChannel = 16
        invalid.mChannelsPerFrame = 2
        XCTAssertFalse(SystemAudioTap.supportsTapFormat(invalid))
        invalid.mBitsPerChannel = 32
        invalid.mFormatFlags = kAudioFormatFlagIsFloat
        invalid.mChannelsPerFrame = 3
        XCTAssertFalse(SystemAudioTap.supportsTapFormat(invalid))
    }


    func testPoolConcurrentClaimAndReleaseDoesNotLeak() {
        let pool = SystemAudioTap.PCMPool(slotCount: 8, bytes: 16)
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "audit.pool", attributes: .concurrent)
        for _ in 0..<1_000 {
            group.enter()
            queue.async {
                if let slot = pool.claim() { slot.release() }
                group.leave()
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 5), .success)
        for _ in 0..<8 { XCTAssertNotNil(pool.claim()) }
        XCTAssertNil(pool.claim())
        pool.releaseAll()
    }

    func testPCMConversionSanitizesNonFiniteValues() {
        XCTAssertEqual(SystemAudioTap.pcm16(.nan), 0)
        XCTAssertEqual(SystemAudioTap.pcm16(.infinity), 0)
        XCTAssertEqual(SystemAudioTap.pcm16(-.infinity), 0)
        XCTAssertEqual(SystemAudioTap.pcm16(1), 32767)
    }
}
