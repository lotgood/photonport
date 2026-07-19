"""Static product-contract checks for the shipped Mac protocol callsites."""
from pathlib import Path
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROJECT_YML = (ROOT / "project.yml").read_text(encoding="utf-8")
TARGETS_YML = PROJECT_YML.split("\ntargets:\n", 1)[1]
PAIRING = (ROOT / "Mac" / "Pairing.swift").read_text(encoding="utf-8")
SENDER = (ROOT / "Mac" / "MacSender.swift").read_text(encoding="utf-8")
INPUT_INJECTOR = (ROOT / "Mac" / "InputInjector.swift").read_text(encoding="utf-8")
SCROLL_COALESCER_PATH = ROOT / "Mac" / "ScrollEventCoalescer.swift"
SCROLL_COALESCER = SCROLL_COALESCER_PATH.read_text(encoding="utf-8") if SCROLL_COALESCER_PATH.exists() else ""
HARNESS = (ROOT / "Tests" / "MacProtocolAdversarialHarness.swift").read_text(encoding="utf-8")
HARNESS_SCRIPT = (ROOT / "scripts" / "test-mac-protocol-adversarial.sh").read_text(encoding="utf-8")
PIN_PATH = ROOT / "Mac" / "ProtocolBuildPin.json"
PARSER_PATH = ROOT / "Mac" / "ProtocolParser.swift"
PARSER = PARSER_PATH.read_text(encoding="utf-8")


def target_block(target_name: str) -> str:
    match = re.search(rf"^  {re.escape(target_name)}:\n(?P<body>(?:    .+\n|      .+\n|        .+\n|          .+\n|            .+\n|              .+\n|                .+\n)*)", TARGETS_YML, re.MULTILINE)
    if not match:
        raise AssertionError(f"missing project.yml target {target_name}")
    return match.group("body")


def swiftc_inputs(script: str) -> set[str]:
    command = script[script.index("xcrun swiftc"):]
    return set(re.findall(r"(?:^|\s)(Mac/[^\s\\]+\.swift|Tests/[^\s\\]+\.swift)", command))

def swift_function(source: str, name: str) -> str:
    start = source.index(f"static func {name}")
    end = source.find("\n    static func ", start + 1)
    return source[start:] if end == -1 else source[start:end]

def swift_private_function(source: str, name: str) -> str:
    match = re.search(rf"private (?:static )?func {re.escape(name)}\b", source)
    if not match:
        raise ValueError(f"missing private function {name}")
    start = match.start()
    end = re.search(r"\n    private (?:static )?func ", source[start + 1:])
    return source[start:] if end is None else source[start:start + 1 + end.start()]


class MacProtocolContractTests(unittest.TestCase):
    def test_wire_versions_and_labels_are_canonical(self):
        self.assertRegex(PAIRING, r"static let version = 2")
        self.assertRegex(PAIRING, r'static let protocolLabel = "PhotonPort-pair-v2"')
        self.assertRegex(PAIRING, r'static let commitLabel = "PhotonPort-pair-v2-commit"')
        self.assertRegex(PAIRING, r"enum SessionCrypto\s*\{\s*static let version = 3")
        self.assertRegex(PAIRING, r'primaryInfo = Data\("PhotonPort-primary-v3"')
        self.assertRegex(PAIRING, r'channelInfo = Data\("PhotonPort-channels-v3"')

    def test_protocol_parser_enforces_canonical_versions_and_proof_fields(self):
        pair_commit = swift_function(PARSER, "parsePairCommit")
        pair_hello = swift_function(PARSER, "parsePairHello")
        server_hello = swift_function(PARSER, "parseServerHello")
        session_accept = swift_function(PARSER, "parseSessionAccept")
        channel_open = swift_function(PARSER, "parseChannelOpen")
        self.assertIn('try int(object, "v") == PairingCrypto.version', pair_commit)
        self.assertIn('try int(object, "v") == PairingCrypto.version', pair_hello)
        self.assertIn('try int(object, "sessionVersion") == SessionCrypto.version', server_hello)
        self.assertIn('try int(object, "v") == SessionCrypto.version', session_accept)
        self.assertIn('base64(try string(object, "sessionID"), bytes: 16)', session_accept)
        self.assertIn('base64(try string(object, "acceptProof"), bytes: 32)', session_accept)
        self.assertIn('try int(object, "v") == SessionCrypto.version', channel_open)
        self.assertIn('base64(try string(object, "proof"), bytes: 32)', channel_open)
    def test_server_hello_is_transport_explicit_and_wifi_seeded(self):
        server_hello = swift_function(PARSER, "parseServerHello")
        self.assertIn("transport: Transport", server_hello)
        self.assertIn('let required = transport == .wifi ? base.union(["wifiSessionSeed"]) : base', server_hello)
        self.assertIn('try string(object, "transport") == (transport == .wifi ? "wifi" : "usb")', server_hello)
        self.assertIn('transport == .wifi ? try base64(try string(object, "wifiSessionSeed"), bytes: 32) : nil', server_hello)
        self.assertIn("wifiSessionSeed: seed", server_hello)
        self.assertNotIn("usbSessionSeed", server_hello)

    def test_uint64_wire_fields_are_strict_and_nonzero_where_required(self):
        session_accept = swift_function(PARSER, "parseSessionAccept")
        channel_open = swift_function(PARSER, "parseChannelOpen")
        parse_control = swift_function(PARSER, "parseControl")
        uint64 = swift_private_function(PARSER, "uint64")
        self.assertIn('guard try uint64(object, "generation") > 0 else', session_accept)
        self.assertIn('guard try uint64(object, "generation") > 0 else', channel_open)
        self.assertIn('case ping(id: UInt64, t: Double)', PARSER)
        self.assertIn('dropped: try uint64(object, "dropped")', parse_control)
        self.assertIn('id: try uint64(object, "id")', PARSER)
        self.assertIn('let max = String(UInt64.max)', uint64)
        self.assertIn('let value = UInt64(digits)', uint64)

    def test_video_payload_matches_canonical_framing_codec_and_keyframe_contract(self):
        video_payload = swift_private_function(SENDER, "videoPayload")
        setup_encoder = swift_private_function(SENDER, "setupEncoder")
        encode = swift_private_function(SENDER, "encode")
        control = swift_private_function(SENDER, "handleControl")
        self.assertIn("annexB.starts(with: startCode3) || annexB.starts(with: startCode4)", video_payload)
        self.assertIn('let codec = hevc ? "hevc-main10-hlg" : "h264"', video_payload)
        self.assertIn('"{\\"codec\\":\\"\\(codec)\\",\\"keyframe\\":\\(keyframe)', video_payload)
        self.assertIn("var telemetryLength = UInt32(telemetry.count).bigEndian", video_payload)
        self.assertIn("payload.append(annexB)", video_payload)
        self.assertIn("guard payload.count <= ProtocolParser.videoDataCap else { return nil }", video_payload)
        self.assertIn("hevcTypes.isSuperset(of: [32, 33, 34]) && hasIRAP", video_payload)
        self.assertIn("h264Types.isSuperset(of: [7, 8]) && hasIDR", video_payload)
        self.assertIn("codecType: kCMVideoCodecType_HEVC", setup_encoder)
        self.assertIn("codecType: kCMVideoCodecType_H264", setup_encoder)
        self.assertIn("kVTProfileLevel_HEVC_Main10_AutoLevel", setup_encoder)
        self.assertIn("kVTEncodeFrameOptionKey_ForceKeyFrame", encode)
        self.assertIn("case .keyframe:", control)
        self.assertIn("needsKeyframe = true", control)

    def test_accept_proof_is_fail_closed_before_binding(self):
        handler = swift_private_function(SENDER, "handleSessionAccept")
        self.assertRegex(handler, r"ProtocolParser\.parseVerifiedSessionAccept")
        verified_accept = swift_function(PARSER, "parseVerifiedSessionAccept")
        self.assertIn("SessionCrypto.constantTimeEqual(proof, expected)", verified_accept)
        self.assertIn("guard SessionCrypto.constantTimeEqual(proof, expected) else", verified_accept)
        self.assertIn("pendingStreamSession = nil", handler)
        self.assertLess(handler.index("parseVerifiedSessionAccept"), handler.index("pendingStreamSession = nil"))

    def test_project_yml_tracks_mac_source_tree_and_keeps_ios_separate(self):
        self.assertTrue(PARSER_PATH.exists(), "Mac/ProtocolParser.swift must be a tracked production source")
        mac_target = target_block("OpenSidecarMac")
        ios_target = target_block("OpenSidecariOS")
        self.assertRegex(mac_target, r"sources:\n\s+- Mac\b")
        self.assertRegex(ios_target, r"sources:\n\s+- iOS\b")
        self.assertNotRegex(mac_target, r"sources:\n(?:\s+- .+\n)*\s+- iOS\b")
        self.assertNotRegex(ios_target, r"sources:\n(?:\s+- .+\n)*\s+- Mac\b")

    def test_parser_is_shared_by_adversarial_harness(self):
        self.assertIn("Mac/ProtocolParser.swift", swiftc_inputs(HARNESS_SCRIPT))
        self.assertIn("Tests/MacProtocolAdversarialHarness.swift", swiftc_inputs(HARNESS_SCRIPT))

    def test_harness_calls_production_parser_without_policy_adapter(self):
        self.assertNotRegex(HARNESS, r"\b(Adapter|PolicyAdapter)\b")
        for symbol in ("ProtocolParser", "framedPayloadLength", "parsePairCommit", "parseSessionAccept", "parseChannelOpen"):
            self.assertIn(symbol, HARNESS)
        self.assertRegex(HARNESS, r"parseSessionAccept[\s\S]*?!= nil")

    def test_parser_caps_are_exact_and_legacy_mebibyte_receives_are_gone(self):
        for cap in ("65_535", "262_144", "16_777_216"):
            self.assertRegex(PARSER, rf"=\s*{cap}\b")
        self.assertNotRegex(SENDER, r"guard\s+\w+\s*>\s*0\s*,\s*\w+\s*<\s*1\s*<<\s*20\s+else")
        self.assertNotRegex(SENDER, r"receive\([^\n]*(?:control|audio)[^\n]*1\s*<<\s*20")

    def test_parse_entry_points_reject_oversized_data_before_decode(self):
        guarded_entry_points = {
            "parsePairCommit": ("pairingCap", "strictObject"),
            "parsePairHello": ("pairingCap", "strictObject"),
            "parseServerHello": ("smallControlCap", "strictObject"),
            "parseSessionAccept": ("smallControlCap", "strictObject"),
            "parseVerifiedSessionAccept": ("smallControlCap", "parseSessionAccept"),
            "parseSessionBusy": ("smallControlCap", "strictObject"),
            "parseChannelOpen": ("smallControlCap", "strictObject"),
            "parseControl": ("smallControlCap", "strictAnyObject"),
        }
        for name, (cap, first_parse_step) in guarded_entry_points.items():
            entry_point = swift_function(PARSER, name)
            guard = f"guard data.count <= {cap} else {{ throw ParseError.invalidFrame }}"
            self.assertIn(guard, entry_point, name)
            self.assertLess(entry_point.index(guard), entry_point.index(first_parse_step), name)

    def test_harness_exercises_oversized_direct_parse_entry_points(self):
        direct_caps = swift_function(HARNESS, "directParserEntryPointCaps")
        self.assertIn("ProtocolParser.pairingCap + 1", direct_caps)
        self.assertIn("ProtocolParser.smallControlCap + 1", direct_caps)
        for symbol in (
            "parsePairCommit",
            "parsePairHello",
            "parseServerHello",
            "parseSessionAccept",
            "parseVerifiedSessionAccept",
            "parseSessionBusy",
            "parseChannelOpen",
            "parseControl",
        ):
            self.assertIn(symbol, direct_caps)
        self.assertIn('expectRejects("\\(name) oversized direct parse")', direct_caps)
    def test_scroll_input_has_conservative_bounds_and_backpressure(self):
        self.assertRegex(PARSER, r"scrollDeltaCap\s*=\s*120\.0\b")
        self.assertIn("Mac/ScrollEventCoalescer.swift", swiftc_inputs(HARNESS_SCRIPT))
        self.assertIn("messageDeltaLimit = 120.0", SCROLL_COALESCER)
        self.assertIn("injectedDeltaLimit = 120.0", SCROLL_COALESCER)
        self.assertIn("pendingWorkCount", SCROLL_COALESCER)
        self.assertIn("ScrollWheelConversion", SCROLL_COALESCER)
        self.assertIn("ScrollEventCoalescer {", INPUT_INJECTOR)
        self.assertIn("callback: @escaping Callback", SCROLL_COALESCER)
        self.assertNotIn("callback: Callback? = nil", SCROLL_COALESCER)
        self.assertIn("init()", SCROLL_COALESCER)
        self.assertIn("init(callback: @escaping Callback", SCROLL_COALESCER)
        self.assertIn("scrollCoalescer.enqueue", INPUT_INJECTOR)
        self.assertIn("nativeWheelDelta", INPUT_INJECTOR)
        self.assertNotIn("scrollQueue.async", INPUT_INJECTOR)
    def test_pairing_and_sender_use_strict_production_parser(self):
        self.assertRegex(PARSER, r"guard\s+\(1\.\.\.cap\(for:\s*kind\)\)\.contains\(length\)\s+else")
        self.assertRegex(PARSER, r"guard\s+payload\.count\s*==\s*expectedLength\s*,\s*\(1\.\.\.cap\(for:\s*kind\)\)\.contains\(payload\.count\)\s+else")
        self.assertRegex(PAIRING, r"ProtocolParser\.(framedPayloadLength|parsePairCommit|parsePairHello)")
        self.assertRegex(SENDER, r"ProtocolParser\.(framedPayloadLength|parseServerHello|parseSessionAccept|parseSessionBusy|parseChannelOpen)")

    def test_application_controls_require_bound_session(self):
        handler = swift_private_function(SENDER, "handleControl")
        gate = "guard connectionReady, boundStreamSession != nil else"
        self.assertIn(gate, handler)
        self.assertLess(handler.index(gate), handler.index("case .touch"))
        self.assertLess(handler.index(gate), handler.index("case .scroll"))
    def test_outbound_control_shapes_match_authority(self):
        ping = swift_private_function(SENDER, "schedulePing")
        cursor = swift_private_function(SENDER, "pollCursorPosition")
        for field in ('\\"type\\":\\"ping\\"', '\\"id\\":\\(pingID)', '\\"t\\":\\(pingTime)'):
            self.assertIn(field, ping)
        for legacy_key in ("drops", "pending", "inp50", "inp95", "capFps"):
            self.assertNotIn(f'\\"{legacy_key}\\"', ping)
        self.assertIn('\\"visible\\":true', cursor)
        self.assertIn('\\"visible\\":false', cursor)
        self.assertNotIn('\\"cursorImg\\"', SENDER)
        self.assertNotRegex(cursor, r'\\"v\\"\s*:')
    def test_mac_has_no_receiver_generation_ownership(self):
        mac_sources = (PARSER, PAIRING, SENDER)
        for symbol in ("parseGenerationSnapshot", "GenerationStore", "SessionOwnershipState"):
            self.assertEqual(sum(source.count(symbol) for source in mac_sources), 0, symbol)

    def test_build_pin_values_and_mac_resource_inclusion_are_exact(self):
        pin = json.loads(PIN_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            pin,
            {
                "schemaVersion": 1,
                "protocolCommit": "b7be72c50249fed978dd56cd44a6c883de01bca8",
                "compatibilityDigest": "6e5e7faf195eff19fafcbdf388186641ef8f8c02586ae1d9f35df0bbc64ae3b3",
                "normativeManifestDigest": "2ff0c5171294afc0b9187dee9229617581f25c9a622692992f148cf6d06e51cc",
            },
        )
        self.assertNotIn("protocolTag", pin)
        self.assertIn('protocolCommit: "b7be72c50249fed978dd56cd44a6c883de01bca8"', SENDER)
        self.assertIn('normativeManifestDigest: "2ff0c5171294afc0b9187dee9229617581f25c9a622692992f148cf6d06e51cc"', SENDER)
        self.assertIn('Bundle.main.url(forResource: "ProtocolBuildPin"', SENDER)
        self.assertIn("try ProtocolBuildPin.validate(at: pinURL)", SENDER)

    def test_mac_target_includes_protocol_build_pin_source_tree(self):
        mac_target = target_block("OpenSidecarMac")
        self.assertTrue(PIN_PATH.is_file(), "Mac/ProtocolBuildPin.json must be a production resource")
        self.assertRegex(mac_target, r"sources:\n\s+- Mac\b")
        self.assertNotRegex(mac_target, r"sources:\n(?:\s+- .+\n)*\s+- iOS\b")

    def test_inbound_frames_validate_before_receive_decode_or_dispatch(self):
        receive_control = swift_private_function(SENDER, "receiveControl")
        self.assertLess(receive_control.index("ProtocolParser.framedPayloadLength"), receive_control.index("conn.receive(minimumIncompleteLength: len"))
        self.assertLess(receive_control.index("ProtocolParser.validatePayload"), receive_control.index("self.handleControl(payload)"))

        receive_audio_hello = swift_private_function(SENDER, "receiveAudioServerHello")
        self.assertLess(receive_audio_hello.index("ProtocolParser.framedPayloadLength"), receive_audio_hello.index("conn.receive(minimumIncompleteLength: length"))
        self.assertLess(receive_audio_hello.index("ProtocolParser.validatePayload"), receive_audio_hello.index("ProtocolParser.parseServerHello"))

        pairing_receive = swift_function(PAIRING, "receive")
        pairing_length = pairing_receive.index("ProtocolParser.framedPayloadLength")
        pairing_payload_receive = pairing_receive.index("conn.receive(minimumIncompleteLength: len")
        pairing_validate = pairing_receive.index("ProtocolParser.validatePayload")
        pairing_decode = pairing_receive.index("PairingWire.decode")
        self.assertLess(pairing_length, pairing_payload_receive)
        self.assertLess(pairing_payload_receive, pairing_validate)
        self.assertLess(pairing_validate, pairing_decode)

    def test_no_unsupported_mac_audio_or_video_data_receive_callbacks(self):
        self.assertNotRegex(SENDER, r"receive(?:Audio|Video)?Data")
        self.assertNotRegex(SENDER, r"ProtocolParser\.framedPayloadLength\(from:[^\n]+kind:\s*\.(?:audioData|videoData)\)")

    def test_outbound_caps_are_directional_and_exact(self):
        send_audio = swift_private_function(SENDER, "sendAudioPCM")
        send_video = swift_private_function(SENDER, "sendFramed")
        send_json = swift_private_function(SENDER, "sendJSONFrame")
        send_audio_open = swift_private_function(SENDER, "receiveAudioServerHello")

        self.assertIn("ProtocolParser.validatePayload(payload, expectedLength: payload.count, kind: .audioData)", send_audio)
        self.assertNotIn(".audioControl", send_audio)
        self.assertIn("ProtocolParser.validatePayload(payload, expectedLength: payload.count, kind: .videoData)", send_video)
        self.assertNotIn(".session", send_video)
        self.assertIn("ProtocolParser.validatePayload(payload, expectedLength: payload.count, kind: .session)", send_json)
        self.assertNotRegex(send_json, r"\.(?:audioData|videoData)\b")
        self.assertIn("PairingWire.frame(open, kind: .audioControl)", send_audio_open)

    def test_begin_session_uses_canonical_phoneinfo_data_without_redecode(self):
        phone_info = SENDER[SENDER.index("struct PhoneInfo"):SENDER.index("/// How the sender reaches")]
        self.assertNotIn("PhoneInfo: Decodable", phone_info)
        self.assertNotIn("CodingKeys", phone_info)
        self.assertNotIn("init(from decoder:", phone_info)
        self.assertNotIn("JSONDecoder().decode(PhoneInfo.self", SENDER)
        self.assertIn("init(_ hello: ProtocolParser.ServerHello)", phone_info)
        self.assertIn("deviceNonce = hello.deviceNonce", phone_info)
        self.assertIn("wifiSessionSeed = hello.wifiSessionSeed", phone_info)
        self.assertNotIn("usbSessionSeed", phone_info)

        begin = swift_private_function(SENDER, "beginSessionHandshake")
        self.assertNotIn("Data(base64Encoded:", begin)
        self.assertNotIn("JSONDecoder", begin)
        self.assertNotIn("Mirror(", begin)
        self.assertIn("let deviceNonce = info.deviceNonce", begin)
        self.assertIn("let ikm = wifiPSK?.key, info.wifiSessionSeed?.count == 32 else", begin)
        self.assertNotIn("usbSessionSeed", begin)

        control = swift_private_function(SENDER, "handleControl")
        self.assertIn("case .serverHello(let parsed):", control)
        self.assertIn("let info = PhoneInfo(parsed)", control)

    def test_app_and_harness_compile_the_same_protocol_parser_without_clone(self):
        mac_target = target_block("OpenSidecarMac")
        self.assertRegex(mac_target, r"sources:\n\s+- Mac\b")
        self.assertIn("Mac/ProtocolParser.swift", swiftc_inputs(HARNESS_SCRIPT))
        self.assertNotRegex(HARNESS_SCRIPT, r"Tests/(?:ProtocolParser|ParserAdapter|.*Protocol.*Clone)\.swift")
        self.assertNotRegex(HARNESS, r"\b(?:ProtocolParserClone|ParserAdapter|PolicyAdapter|struct\s+ProtocolParser|enum\s+ProtocolParser)\b")


if __name__ == "__main__":
    unittest.main()
