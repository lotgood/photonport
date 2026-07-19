// SPDX-License-Identifier: GPL-3.0-only
// Part of PhotonPort, a GPL-3.0 fork of OpenDisplay
// (https://github.com/peetzweg/opendisplay, (c) peetzweg and contributors).
// This file (c) 2026 hyupji, added in the fork.

// EDRToHLGConverter — owns the EDR→HLG mapping the HDR extend path needs.
//
// CGDisplayStream delivers the virtual display's EDR composite as float16
// extended-sRGB. Handing that straight to VideoToolbox works, but VT picks
// its own reference point for the HLG conversion — measured on device it
// stretches the Mac's ~4-5× EDR headroom across the FULL HLG range, which a
// panel with 16× headroom then renders blindingly bright with crushed
// highlight detail. This Metal pass pins the mapping to the BT.2408
// convention instead: SDR white = 203 nits = HLG signal 0.75, nominal peak
// = 1000 nits = signal 1.0. A 4× highlight on the Mac renders as a 4×
// highlight on the device — no more, no less.
//
// float16 extended-sRGB RGBA  ──►  10-bit 4:2:0 HLG BT.2020 ('x420')
//   decode sRGB transfer → BT.709→BT.2020 primaries → scale by 203/1000
//   → HLG OETF → non-constant-luminance Y'CbCr (video range) → p010 words

import Foundation
import Metal
import CoreVideo

final class EDRToHLGConverter {
    private static let referenceWhiteSceneLinear: Float = 0.26496256
    private let device: MTLDevice
    private let commandQueue: MTLCommandQueue
    private let pipeline: MTLComputePipelineState
    private var textureCache: CVMetalTextureCache?
    private var pool: CVPixelBufferPool?
    private var poolSize = (w: 0, h: 0)

    convenience init?() {
        self.init(deviceFactory: MTLCreateSystemDefaultDevice,
                  commandQueueFactory: { $0.makeCommandQueue() })
    }

    init?(device: MTLDevice, commandQueue: MTLCommandQueue) {
        self.device = device
        self.commandQueue = commandQueue

        // Compiled from source so the project needs no .metal build phase
        // (same pattern as the iOS MetalVideoRenderer).
        let source = """
        #include <metal_stdlib>
        using namespace metal;

        inline float srgbToLinearExt(float v) {
            float a = fabs(v);
            float l = a <= 0.04045f ? a / 12.92f : pow((a + 0.055f) / 1.055f, 2.4f);
            return copysign(l, v);
        }
        inline float hlgOETF(float e) {   // e: scene linear 0..1 (1.0 = 1000 nits)
            const float a = 0.17883277f, b = 0.28466892f, c = 0.55991073f;
            return e <= 1.0f / 12.0f ? sqrt(3.0f * e) : a * log(12.0f * e - b) + c;
        }
        // Encoded R'G'B' for one source pixel.
        inline float3 encodePixel(float4 s) {
            float3 lin = float3(srgbToLinearExt(s.r), srgbToLinearExt(s.g), srgbToLinearExt(s.b));
            // BT.709 → BT.2020 primaries (linear light).
            float3 lin2020 = float3(
                dot(float3(0.6274f, 0.3293f, 0.0433f), lin),
                dot(float3(0.0691f, 0.9195f, 0.0114f), lin),
                dot(float3(0.0164f, 0.0880f, 0.8956f), lin));
            // BT.2408 receiver decision: 203-nit SDR white is HLG signal 0.75.
            // The inverse HLG OETF of 0.75 is 0.26496256 scene-linear.
            float3 e = clamp(lin2020 * 0.26496256f, 0.0f, 1.0f);
            return float3(hlgOETF(e.r), hlgOETF(e.g), hlgOETF(e.b));
        }
        // One thread per 2x2 block: 4 luma samples + 1 subsampled chroma pair.
        kernel void edr2hlg(texture2d<float, access::read> src [[texture(0)]],
                            texture2d<uint, access::write> lum [[texture(1)]],
                            texture2d<uint, access::write> chr [[texture(2)]],
                            uint2 gid [[thread_position_in_grid]]) {
            uint2 base = gid * 2;
            if (base.x + 1 >= src.get_width() || base.y + 1 >= src.get_height()) return;
            float3 sum = 0.0f;
            for (uint dy = 0; dy < 2; dy++) {
                for (uint dx = 0; dx < 2; dx++) {
                    uint2 p = base + uint2(dx, dy);
                    float3 rgb = encodePixel(src.read(p));
                    sum += rgb;
                    // BT.2020 NCL luma, 10-bit video range, p010 high bits.
                    float y = dot(float3(0.2627f, 0.6780f, 0.0593f), rgb);
                    uint yd = (uint)clamp(round(y * 876.0f + 64.0f), 64.0f, 940.0f);
                    lum.write(yd << 6, p);
                }
            }
            float3 avg = sum * 0.25f;
            float y = dot(float3(0.2627f, 0.6780f, 0.0593f), avg);
            float cb = (avg.b - y) / 1.8814f;
            float cr = (avg.r - y) / 1.4746f;
            uint cbd = (uint)clamp(round(cb * 896.0f + 512.0f), 64.0f, 960.0f);
            uint crd = (uint)clamp(round(cr * 896.0f + 512.0f), 64.0f, 960.0f);
            chr.write(uint4(cbd << 6, crd << 6, 0, 0), gid);
        }
        """
        let lib: MTLLibrary
        do { lib = try device.makeLibrary(source: source, options: nil) }
        catch { Log.info("EDR→HLG shader compile failed: \(error)"); return nil }
        guard let fn = lib.makeFunction(name: "edr2hlg") else { return nil }
        do { pipeline = try device.makeComputePipelineState(function: fn) }
        catch { Log.info("EDR→HLG pipeline failed: \(error)"); return nil }
        guard CVMetalTextureCacheCreate(nil, nil, device, nil, &textureCache) == kCVReturnSuccess,
              textureCache != nil else { return nil }
    }
    convenience init?(deviceFactory: () -> MTLDevice?,
                      commandQueueFactory: (MTLDevice) -> MTLCommandQueue?) {
        guard let device = deviceFactory(),
              let commandQueue = commandQueueFactory(device) else { return nil }
        self.init(device: device, commandQueue: commandQueue)
    }
    static func hlgSignal(forLinearSDR value: Float) -> Float {
        let e = min(max(value * referenceWhiteSceneLinear, 0), 1)
        if e <= 1 / 12 { return sqrt(3 * e) }
        return 0.17883277 * log(12 * e - 0.28466892) + 0.55991073
    }

    static func p010Luma(forHLGSignal value: Float) -> UInt16 {
        let code = min(max((value * 876).rounded() + 64, 64), 940)
        return UInt16(code) << 6
    }

    private func makePool(width: Int, height: Int) -> CVPixelBufferPool? {
        let attrs: [CFString: Any] = [
            kCVPixelBufferPixelFormatTypeKey: kCVPixelFormatType_420YpCbCr10BiPlanarVideoRange,
            kCVPixelBufferWidthKey: width,
            kCVPixelBufferHeightKey: height,
            kCVPixelBufferIOSurfacePropertiesKey: [:] as CFDictionary,
            kCVPixelBufferMetalCompatibilityKey: true,
        ]
        var pool: CVPixelBufferPool?
        guard CVPixelBufferPoolCreate(nil, nil, attrs as CFDictionary, &pool) == kCVReturnSuccess else {
            return nil
        }
        return pool
    }

    /// Synchronous (~1ms) — called on the capture queue per frame.
    func convert(_ src: CVPixelBuffer) -> CVPixelBuffer? {
        guard let cache = textureCache else { return nil }
        let width = CVPixelBufferGetWidth(src) & ~1
        let height = CVPixelBufferGetHeight(src) & ~1
        guard width > 0, height > 0 else { return nil }
        if pool == nil || poolSize.w != width || poolSize.h != height {
            pool = makePool(width: width, height: height)
            poolSize = (width, height)
        }
        guard let pool else { return nil }
        var outBuffer: CVPixelBuffer?
        guard CVPixelBufferPoolCreatePixelBuffer(nil, pool, &outBuffer) == kCVReturnSuccess,
              let out = outBuffer else { return nil }

        var cvSrc: CVMetalTexture?
        var cvLum: CVMetalTexture?
        var cvChr: CVMetalTexture?
        guard CVMetalTextureCacheCreateTextureFromImage(
            nil, cache, src, nil, .rgba16Float,
            CVPixelBufferGetWidth(src), CVPixelBufferGetHeight(src), 0, &cvSrc) == kCVReturnSuccess,
            CVMetalTextureCacheCreateTextureFromImage(
                nil, cache, out, nil, .r16Uint, width, height, 0, &cvLum) == kCVReturnSuccess,
            CVMetalTextureCacheCreateTextureFromImage(
                nil, cache, out, nil, .rg16Uint, width / 2, height / 2, 1, &cvChr) == kCVReturnSuccess else {
            return nil
        }
        guard let cvSrc, let cvLum, let cvChr,
              let texSrc = CVMetalTextureGetTexture(cvSrc),
              let texLum = CVMetalTextureGetTexture(cvLum),
              let texChr = CVMetalTextureGetTexture(cvChr),
              let cmd = commandQueue.makeCommandBuffer(),
              let enc = cmd.makeComputeCommandEncoder() else { return nil }
        enc.setComputePipelineState(pipeline)
        enc.setTexture(texSrc, index: 0)
        enc.setTexture(texLum, index: 1)
        enc.setTexture(texChr, index: 2)
        let grid = MTLSize(width: width / 2, height: height / 2, depth: 1)
        let tg = MTLSize(width: 16, height: 16, depth: 1)
        enc.dispatchThreads(grid, threadsPerThreadgroup: tg)
        enc.endEncoding()
        cmd.commit()
        cmd.waitUntilCompleted()
        guard cmd.status == .completed, cmd.error == nil else { return nil }

        // Already HLG/BT.2020 — tag so VideoToolbox passes values through
        // instead of converting a second time.
        CVBufferSetAttachment(out, kCVImageBufferColorPrimariesKey,
                              kCVImageBufferColorPrimaries_ITU_R_2020, .shouldPropagate)
        CVBufferSetAttachment(out, kCVImageBufferTransferFunctionKey,
                              kCVImageBufferTransferFunction_ITU_R_2100_HLG, .shouldPropagate)
        CVBufferSetAttachment(out, kCVImageBufferYCbCrMatrixKey,
                              kCVImageBufferYCbCrMatrix_ITU_R_2020, .shouldPropagate)
        return out
    }
}
