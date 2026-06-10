// MetalVideoRenderer — experimental low-latency display path.
//
// AVSampleBufferDisplayLayer hides decode and presentation scheduling and is
// suspected of buffering ~1 extra frame (moonlight-qt ships a Metal path for
// the same reason). Here the receiver decodes explicitly with
// VTDecompressionSession and hands us BGRA pixel buffers; we draw them onto a
// CAMetalLayer and present immediately. The drawable's presented handler
// reports when the frame actually hit the glass — the only true
// "capture→photon" measurement point available on iOS.

import Foundation
import Metal
import QuartzCore
import CoreVideo

final class MetalVideoRenderer {
    let metalLayer = CAMetalLayer()
    private let device: MTLDevice
    private let commandQueue: MTLCommandQueue
    private let pipeline: MTLRenderPipelineState
    private var textureCache: CVMetalTextureCache?

    /// presentedTime (CACurrentMediaTime base) + the capture timestamp that
    /// was threaded through render(_:captureMs:).
    var onPresented: ((_ presentedTime: CFTimeInterval, _ captureMs: Double?) -> Void)?

    init?() {
        guard let device = MTLCreateSystemDefaultDevice(),
              let queue = device.makeCommandQueue() else { return nil }
        self.device = device
        self.commandQueue = queue

        // Fullscreen textured quad; compiled from source so the project needs
        // no .metal build phase.
        let source = """
        #include <metal_stdlib>
        using namespace metal;
        struct VOut { float4 pos [[position]]; float2 uv; };
        vertex VOut vmain(uint vid [[vertex_id]]) {
            float2 p[4] = { float2(-1,-1), float2(1,-1), float2(-1,1), float2(1,1) };
            VOut o;
            o.pos = float4(p[vid], 0, 1);
            o.uv = float2((p[vid].x + 1.0) * 0.5, (1.0 - p[vid].y) * 0.5);
            return o;
        }
        fragment float4 fmain(VOut in [[stage_in]],
                              texture2d<float> tex [[texture(0)]]) {
            constexpr sampler s(filter::linear);
            return tex.sample(s, in.uv);
        }
        """
        guard let lib = try? device.makeLibrary(source: source, options: nil),
              let vfn = lib.makeFunction(name: "vmain"),
              let ffn = lib.makeFunction(name: "fmain") else { return nil }
        let desc = MTLRenderPipelineDescriptor()
        desc.vertexFunction = vfn
        desc.fragmentFunction = ffn
        desc.colorAttachments[0].pixelFormat = .bgra8Unorm
        guard let pso = try? device.makeRenderPipelineState(descriptor: desc) else { return nil }
        pipeline = pso

        metalLayer.device = device
        metalLayer.pixelFormat = .bgra8Unorm
        metalLayer.framebufferOnly = true
        metalLayer.isOpaque = true
        // 2 = one drawable on glass, one being filled. Minimum queueing;
        // nextDrawable() blocking is our natural pacing.
        metalLayer.maximumDrawableCount = 2
        CVMetalTextureCacheCreate(nil, nil, device, nil, &textureCache)
    }

    /// Called on the receiver's queue — Metal encoding off-main is fine.
    func render(_ pixelBuffer: CVPixelBuffer, captureMs: Double?) {
        let w = CVPixelBufferGetWidth(pixelBuffer)
        let h = CVPixelBufferGetHeight(pixelBuffer)
        if metalLayer.drawableSize != CGSize(width: w, height: h) {
            metalLayer.drawableSize = CGSize(width: w, height: h)
        }

        guard let cache = textureCache else { return }
        var cvTexture: CVMetalTexture?
        CVMetalTextureCacheCreateTextureFromImage(
            nil, cache, pixelBuffer, nil, .bgra8Unorm, w, h, 0, &cvTexture)
        guard let cvTexture, let texture = CVMetalTextureGetTexture(cvTexture) else { return }

        guard let drawable = metalLayer.nextDrawable(),
              let cmd = commandQueue.makeCommandBuffer() else { return }
        let pass = MTLRenderPassDescriptor()
        pass.colorAttachments[0].texture = drawable.texture
        pass.colorAttachments[0].loadAction = .dontCare
        pass.colorAttachments[0].storeAction = .store
        guard let encoder = cmd.makeRenderCommandEncoder(descriptor: pass) else { return }
        encoder.setRenderPipelineState(pipeline)
        encoder.setFragmentTexture(texture, index: 0)
        encoder.drawPrimitives(type: .triangleStrip, vertexStart: 0, vertexCount: 4)
        encoder.endEncoding()

        drawable.addPresentedHandler { [weak self] d in
            self?.onPresented?(d.presentedTime, captureMs)
        }
        // Keep the source texture alive until the GPU is done with it.
        cmd.addCompletedHandler { _ in _ = cvTexture }
        cmd.present(drawable)
        cmd.commit()
    }
}
