import CoreVideo
import XCTest
@testable import PhotonPort

final class S02HDRTests: XCTestCase {
    func testReferenceWhiteGoldenVectors() {
        XCTAssertEqual(EDRToHLGConverter.hlgSignal(forLinearSDR: 0), 0, accuracy: 0.000_001)
        XCTAssertEqual(EDRToHLGConverter.hlgSignal(forLinearSDR: 1), 0.75, accuracy: 0.000_001)
        XCTAssertEqual(EDRToHLGConverter.hlgSignal(forLinearSDR: 10), 1, accuracy: 0.000_001)
        XCTAssertEqual(EDRToHLGConverter.p010Luma(forHLGSignal: 0.75), 721 << 6)
        XCTAssertEqual(EDRToHLGConverter.p010Luma(forHLGSignal: -1), 64 << 6)
        XCTAssertEqual(EDRToHLGConverter.p010Luma(forHLGSignal: 2), 940 << 6)
    }

    func testP010ConversionUsesReferenceWhite() throws {
        guard let converter = EDRToHLGConverter() else {
            throw XCTSkip("Metal is unavailable")
        }
        let output = converter.convert(try whiteSource())
        guard let output else {
            throw XCTSkip("The local Metal device cannot create the audit conversion textures")
        }
        XCTAssertEqual(CVPixelBufferGetPixelFormatType(output), kCVPixelFormatType_420YpCbCr10BiPlanarVideoRange)
        CVPixelBufferLockBaseAddress(output, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(output, .readOnly) }
        let luma = CVPixelBufferGetBaseAddressOfPlane(output, 0)!.assumingMemoryBound(to: UInt16.self)
        XCTAssertEqual(luma[0], EDRToHLGConverter.p010Luma(forHLGSignal: 0.75))
    }

    func testUnavailableCommandQueueFailsConverterCreation() {
        XCTAssertNil(EDRToHLGConverter(
            deviceFactory: MTLCreateSystemDefaultDevice,
            commandQueueFactory: { _ in nil }))
    }

    private func whiteSource() throws -> CVPixelBuffer {
        let attributes: [CFString: Any] = [
            kCVPixelBufferIOSurfacePropertiesKey: [:] as CFDictionary,
            kCVPixelBufferMetalCompatibilityKey: true,
        ]
        var buffer: CVPixelBuffer?
        XCTAssertEqual(CVPixelBufferCreate(nil, 2, 2, kCVPixelFormatType_64RGBAHalf,
                                            attributes as CFDictionary, &buffer), kCVReturnSuccess)
        guard let buffer else { throw XCTSkip("Cannot allocate float16 source") }
        CVPixelBufferLockBaseAddress(buffer, [])
        defer { CVPixelBufferUnlockBaseAddress(buffer, []) }
        let pixels = CVPixelBufferGetBaseAddress(buffer)!.assumingMemoryBound(to: UInt16.self)
        for index in 0..<16 { pixels[index] = Float16(1).bitPattern }
        return buffer
    }
}
