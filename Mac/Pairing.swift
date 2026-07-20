// SPDX-License-Identifier: GPL-3.0-only
// Part of PhotonPort, a GPL-3.0 fork of OpenDisplay
// (https://github.com/peetzweg/opendisplay, (c) peetzweg and contributors).
// This file (c) 2026 hyupji, added in the fork.

// Pairing (Mac side) — establishes a long-term per-device secret so WiFi
// sessions can run over TLS-PSK instead of plaintext TCP.
//
// Protocol (mutual SAS numeric comparison with a commitment phase, in the
// spirit of Bluetooth Numeric Comparison / ZRTP):
//   1. While the device's pairing screen is open it advertises a short-lived
//      pairing instance (the video service type carrying a `pair=1` TXT
//      flag). No standing unauthenticated surface otherwise.
//   2. Each side generates an ephemeral X25519 key + 16-byte nonce and first
//      exchanges a HASH COMMITMENT over (role, installID, name, pub, nonce).
//      Only after both commitments are in does each side REVEAL its opening;
//      the peer aborts unless the reveal hashes back to the earlier commit.
//   3. Both derive a 6-digit SAS and a 32-byte PSK from the ECDH secret and a
//      transcript of both openings. The SAS is shown on BOTH screens; the
//      human confirming the two codes match is the authentication. The PSK is
//      stored only on that confirmation and is never sent on the wire.
//
// Why the commitment matters: without committing before revealing, an active
// same-LAN MITM running fake endpoints on both legs could grind its own
// ephemeral key/nonce until both screens show the SAME 6-digit code (~10^6
// offline trials) and defeat the human check. Committing first binds each
// party to its keys before it can see the peer's, so the attacker is reduced
// to a 1-in-10^6 online guess per attempt. No low-entropy secret is ever
// transmitted, so there is no offline PIN oracle. Framing is the app's usual
// [4-byte BE length][JSON payload].

import Foundation
import Network
import CryptoKit
import LocalAuthentication

// MARK: - Wire messages

// Two message types flow in both directions. First a PairCommit (a hash of
// the opening below) is exchanged; only then is the PairHello opening revealed
// and checked against the peer's earlier commit. No low-entropy secret (PIN)
// is ever transmitted — authentication is the human comparing the derived SAS
// on both screens, which the commitment phase makes ungrindable.
struct PairHello: Codable, Sendable {
    var type = "pair-hello"
    let v: Int              // protocol version (2)
    let role: String        // "mac" | "device"
    let installID: String
    let name: String?       // Mac's user-visible name (device omits)
    let pub: String         // X25519 public key, base64
    let nonce: String       // 16 random bytes, base64
}

// Hash commitment to an opening, exchanged before the opening is revealed.
struct PairCommit: Codable, Sendable {
    var type = "pair-commit"
    let v: Int
    let commit: String      // base64 of the 32-byte SHA-256 commitment
}

// MARK: - Stream session v3 messages

struct SessionOpen: Codable, Sendable {
    var type = "session-open"
    let v: Int
    let macInstallID: String
    let deviceInstallID: String
    let macNonce: String
    let primaryProof: String
}

struct SessionAccept: Codable, Sendable {
    var type = "session-accept"
    let v: Int
    let sessionID: String
    let generation: UInt64
    let acceptProof: String
}

struct SessionBusy: Codable, Sendable {
    var type = "session-busy"
    let v: Int
    let reason: String
}

struct SessionChannelOpen: Codable, Sendable {
    var type = "channel-open"
    let v: Int
    let macInstallID: String
    let sessionID: String
    let generation: UInt64
    let channel: String
    let nonce: String
    let proof: String
}

/// Controller-owned session state. A generation is a lease: asynchronous
/// Keeping this reducer independent from Network.framework makes the busy,
/// Controller-owned session state. A generation is a lease: asynchronous
/// completion may mutate a session only while it still owns that generation.
enum SessionLifecycleState: Equatable, Sendable {
    case starting(UInt64)
    case connected(UInt64)
    case failed(UInt64, String)
    case stopping(UInt64)
    case stopped(UInt64)

    var generation: UInt64 {
        switch self {
        case .starting(let generation), .connected(let generation),
             .failed(let generation, _), .stopping(let generation),
             .stopped(let generation):
            return generation
        }
    }

    static func mayTransition(from state: SessionLifecycleState,
                              to next: SessionLifecycleState) -> Bool {
        guard state.generation == next.generation else { return false }
        switch (state, next) {
        case (.starting, .connected), (.starting, .failed), (.starting, .stopping),
             (.connected, .stopping), (.failed, .stopping), (.stopping, .stopped):
            return true
        default:
            return false
        }
    }
}


enum SessionTiming {
    static let macDisconnectGrace: TimeInterval = 10
    static let handshakeTimeout: TimeInterval = 5
    static let livenessDeadline: TimeInterval = 5
    static let busyRetryDelay: TimeInterval = 5
}

// MARK: - Crypto core (identical on both platforms)

enum PairingCrypto {
    // See iOS/Pairing.swift: pairing reuses the authorized video service
    // type with a `pair=1` TXT flag rather than a dedicated type (which
    // would need its own Local Network authorization).
    static let serviceType = "_photonport._tcp"
    static let pairTXTKey = "pair"
    static let version = 2
    static let protocolLabel = "PhotonPort-pair-v2"
    static let commitLabel = "PhotonPort-pair-v2-commit"

    static func randomNonce() -> Data? {
        var b = Data(count: 16)
        let ok = b.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
        }
        return ok == errSecSuccess ? b : nil
    }

    /// Hash commitment over an opening (role, install id, name, pub, nonce).
    /// Exchanged BEFORE the opening is revealed: once a side has sent its
    /// commit it can no longer change any of these without the peer noticing,
    /// which is what forecloses SAS grinding by an active MITM.
    static func commitment(role: String, installID: String, name: String?,
                           pub: Data, nonce: Data) -> Data {
        var h = SHA256()
        func feed(_ d: Data) {
            var n = UInt32(d.count).bigEndian
            h.update(data: Data(bytes: &n, count: 4))
            h.update(data: d)
        }
        feed(Data(commitLabel.utf8))
        feed(Data(role.utf8))
        feed(Data(installID.utf8))
        feed(Data((name ?? "").utf8))
        feed(pub); feed(nonce)
        return Data(h.finalize())
    }

    /// Length-prefixed, role-ordered transcript binding everything that
    /// identifies this exact session, so a MITM cannot misbind or reflect:
    /// protocol label, both install IDs, both ephemeral public keys, and both
    /// nonces (client = Mac, server = device). Bonjour service name is
    /// deliberately excluded — it's user-editable and Bonjour may uniquify
    /// it, which would desync the two transcripts.
    static func transcript(macInstallID: String, deviceInstallID: String,
                           macPub: Data, devicePub: Data,
                           macNonce: Data, deviceNonce: Data) -> Data {
        var h = SHA256()
        func feed(_ d: Data) {
            var n = UInt32(d.count).bigEndian
            h.update(data: Data(bytes: &n, count: 4))
            h.update(data: d)
        }
        feed(Data(protocolLabel.utf8))
        feed(Data(macInstallID.utf8))
        feed(Data(deviceInstallID.utf8))
        feed(macPub); feed(devicePub); feed(macNonce); feed(deviceNonce)
        return Data(h.finalize())
    }

    /// 6-digit short authentication string derived from the ECDH secret and
    /// the transcript. Displayed on BOTH devices for the user to compare.
    static func sasDigits(shared: SharedSecret, transcript: Data) -> String {
        let k = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: transcript,
            sharedInfo: Data("photonport-pair-sas-v2".utf8), outputByteCount: 4)
        let bytes = k.withUnsafeBytes { Array($0) }
        // Platform-independent big-endian assembly.
        let v = (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16)
              | (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
        return String(format: "%06u", v % 1_000_000)
    }

    /// The long-term TLS-PSK, derived only from the ECDH secret + transcript
    /// (never from the SAS), so the displayed code carries no key material.
    static func psk(shared: SharedSecret, transcript: Data) -> Data {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: transcript,
            sharedInfo: Data("photonport-pair-psk-v2".utf8), outputByteCount: 32)
            .withUnsafeBytes { Data($0) }
    }

    /// Client-side TLS-PSK options. TLS 1.2 PSK ciphersuite — the
    /// combination Network.framework's PSK API actually negotiates
    /// (verified against live listeners on macOS 26 and 27).
    static func clientTLSOptions(identity: String, psk: Data) -> NWProtocolTLS.Options {
        let opts = NWProtocolTLS.Options()
        addPSK(opts, identity: identity, psk: psk)
        return opts
    }

    static func addPSK(_ opts: NWProtocolTLS.Options, identity: String, psk: Data) {
        let pskDD = psk.withUnsafeBytes { DispatchData(bytes: $0) }
        let idDD = Data(identity.utf8).withUnsafeBytes { DispatchData(bytes: $0) }
        sec_protocol_options_add_pre_shared_key(opts.securityProtocolOptions,
                                                pskDD as __DispatchData,
                                                idDD as __DispatchData)
        sec_protocol_options_append_tls_ciphersuite(
            opts.securityProtocolOptions,
            tls_ciphersuite_t(rawValue: UInt16(TLS_PSK_WITH_AES_128_GCM_SHA256))!)
        sec_protocol_options_set_min_tls_protocol_version(opts.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_max_tls_protocol_version(opts.securityProtocolOptions, .TLSv12)
    }
}

// MARK: - Stream session crypto (identical on both platforms)

enum SessionCrypto {
    static let version = 3
    private static let primaryInfo = Data("PhotonPort-primary-v3".utf8)
    private static let channelInfo = Data("PhotonPort-channels-v3".utf8)

    static func randomBytes(count: Int) -> Data? {
        guard count > 0 else { return Data() }
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        return status == errSecSuccess ? data : nil
    }

    static func lengthPrefixed(_ fields: [Data]) -> Data {
        var result = Data()
        for field in fields {
            var count = UInt32(field.count).bigEndian
            result.append(Data(bytes: &count, count: MemoryLayout<UInt32>.size))
            result.append(field)
        }
        return result
    }

    static func primaryKey(ikm: Data, macInstallID: String, deviceInstallID: String,
                           macNonce: Data, deviceNonce: Data) -> SymmetricKey {
        let saltInput = lengthPrefixed([
            uint64Data(UInt64(version)), Data(macInstallID.utf8),
            Data(deviceInstallID.utf8), macNonce, deviceNonce,
        ])
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: Data(SHA256.hash(data: saltInput)),
            info: primaryInfo,
            outputByteCount: 32)
    }

    static func channelSecret(primaryKey: SymmetricKey, sessionID: Data,
                              generation: UInt64) -> SymmetricKey {
        let saltInput = lengthPrefixed([sessionID, uint64Data(generation)])
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: primaryKey,
            salt: Data(SHA256.hash(data: saltInput)),
            info: channelInfo,
            outputByteCount: 32)
    }

    static func primaryProof(key: SymmetricKey, macInstallID: String,
                             deviceInstallID: String, macNonce: Data,
                             deviceNonce: Data) -> Data {
        authenticate(key: key, fields: [
            Data("session-open".utf8), uint64Data(UInt64(version)),
            Data(macInstallID.utf8), Data(deviceInstallID.utf8),
            macNonce, deviceNonce,
        ])
    }

    static func acceptProof(key: SymmetricKey, sessionID: Data, generation: UInt64,
                            macInstallID: String, deviceInstallID: String,
                            macNonce: Data, deviceNonce: Data) -> Data {
        authenticate(key: key, fields: [
            Data("session-accept".utf8), sessionID, uint64Data(generation),
            Data(macInstallID.utf8), Data(deviceInstallID.utf8),
            macNonce, deviceNonce,
        ])
    }

    static func channelProof(key: SymmetricKey, sessionID: Data, generation: UInt64,
                             channel: String, nonce: Data) -> Data {
        authenticate(key: key, fields: [
            Data("channel-open".utf8), uint64Data(UInt64(version)), sessionID,
            uint64Data(generation), Data(channel.utf8), nonce,
        ])
    }

    /// Single audited comparison primitive for fixed-length cryptographic values.
    /// It rejects differing lengths before scanning every byte without an early exit.
    static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in lhs.indices {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }

    static func data(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    private static func authenticate(key: SymmetricKey, fields: [Data]) -> Data {
        Data(HMAC<SHA256>.authenticationCode(
            for: lengthPrefixed(fields), using: key))
    }

    private static func uint64Data(_ value: UInt64) -> Data {
        var bigEndian = value.bigEndian
        return Data(bytes: &bigEndian, count: MemoryLayout<UInt64>.size)
    }
}

// MARK: - Protocol 2d2c613 USB authenticated channel

struct USBPrefaceMessage: Codable, Equatable, Sendable {
    let type: String
    let v: Int
    let macInstallID: String
    let deviceInstallID: String
    let purpose: String
    let macNonce: String
    let deviceNonce: String?
    let proof: String

    static let magic = Data([0x50, 0x50, 0x55, 0x53, 0x42, 0x31, 0x00, 0x00])
    static let frameCap = 4_096

    static func frame(_ message: USBPrefaceMessage) -> Data? {
        guard let payload = try? JSONEncoder().encode(message), valid(message, expectedType: message.type) else { return nil }
        return prefaceFrame(payload)
    }

    static func prefaceFrame(_ payload: Data) -> Data? {
        guard !payload.isEmpty, payload.count <= frameCap else { return nil }
        var length = UInt32(payload.count).bigEndian
        return Data(bytes: &length, count: 4) + payload
    }

    static func unframe(_ data: Data) -> (Data, Data)? {
        guard data.count >= 4 else { return nil }
        let length = data.prefix(4).withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
        guard length > 0, length <= frameCap, data.count >= 4 + Int(length) else { return nil }
        return (Data(data[4..<(4 + Int(length))]), Data(data.dropFirst(4 + Int(length))))
    }

    static func decode(_ payload: Data, expectedType: String) -> USBPrefaceMessage? {
        guard !payload.isEmpty, payload.count <= frameCap,
              duplicateFreeTopLevelObject(payload),
              let rawObject = try? JSONSerialization.jsonObject(with: payload),
              let object = rawObject as? [String: Any],
              let type = object["type"] as? String,
              exactKeys(object, type: type),
              let message = try? JSONDecoder().decode(USBPrefaceMessage.self, from: payload),
              valid(message, expectedType: expectedType) else { return nil }
        return message
    }

    static func valid(_ message: USBPrefaceMessage, expectedType: String) -> Bool {
        guard ["usb-bind-init", "usb-bind-challenge", "usb-bind-finish", "usb-bind-accept"].contains(message.type) else {
            return false
        }
        guard message.type == expectedType, message.v == 1, bounded(message.macInstallID),
              bounded(message.deviceInstallID), message.purpose == "primary" || message.purpose == "audio",
              canonicalBase64(message.macNonce, count: 32), canonicalBase64(message.proof, count: 32) else { return false }
        return message.type == "usb-bind-init"
            ? message.deviceNonce == nil
            : message.deviceNonce.map { canonicalBase64($0, count: 32) } ?? false
    }
    private static func exactKeys(_ object: [String: Any], type: String) -> Bool {
        switch type {
        case "usb-bind-init":
            return Set(object.keys) == ["type", "v", "macInstallID", "deviceInstallID", "purpose", "macNonce", "proof"]
        case "usb-bind-challenge", "usb-bind-finish", "usb-bind-accept":
            return Set(object.keys) == ["type", "v", "macInstallID", "deviceInstallID", "purpose", "macNonce", "deviceNonce", "proof"]
        default:
            return false
        }
    }

    private static func bounded(_ value: String) -> Bool { !value.isEmpty && value.utf8.count <= 256 }
    static func canonicalBase64(_ value: String, count: Int) -> Bool {
        guard let decoded = Data(base64Encoded: value), decoded.count == count else { return false }
        return decoded.base64EncodedString() == value
    }

    /// Reject duplicate top-level names before Foundation's permissive JSON parser sees them.
    private static func duplicateFreeTopLevelObject(_ data: Data) -> Bool {
        guard let source = String(data: data, encoding: .utf8) else { return false }
        var index = source.startIndex
        func whitespace() { while index < source.endIndex && source[index].isWhitespace { index = source.index(after: index) } }
        func string() -> String? {
            guard index < source.endIndex, source[index] == "\"" else { return nil }
            index = source.index(after: index); var result = ""; var escaped = false
            while index < source.endIndex {
                let c = source[index]; index = source.index(after: index)
                if escaped { result.append(c); escaped = false }
                else if c == "\\" { escaped = true }
                else if c == "\"" { return result }
                else { result.append(c) }
            }
            return nil
        }
        whitespace(); guard index < source.endIndex, source[index] == "{" else { return false }
        index = source.index(after: index); var keys = Set<String>(); whitespace()
        if index < source.endIndex, source[index] == "}" { return false }
        while index < source.endIndex {
            guard let key = string(), keys.insert(key).inserted else { return false }
            whitespace(); guard index < source.endIndex, source[index] == ":" else { return false }
            index = source.index(after: index); whitespace()
            var depth = 0; var quoted = false; var escaped = false
            while index < source.endIndex {
                let c = source[index]
                if quoted { if escaped { escaped = false } else if c == "\\" { escaped = true } else if c == "\"" { quoted = false } }
                else if c == "\"" { quoted = true } else if c == "{" || c == "[" { depth += 1 } else if c == "}" || c == "]" { if depth == 0 { break }; depth -= 1 } else if c == "," && depth == 0 { break }
                index = source.index(after: index)
            }
            whitespace()
            guard index < source.endIndex else { return false }
            if source[index] == "}" { index = source.index(after: index); whitespace(); return index == source.endIndex }
            guard source[index] == "," else { return false }
            index = source.index(after: index); whitespace()
        }
        return false
    }
}

enum USBChannelCrypto {
    static func authKey(psk: Data, macInstallID: String, deviceInstallID: String, purpose: String) -> SymmetricKey? {
        guard valid(psk, macInstallID, deviceInstallID, purpose) else { return nil }
        return derive(psk, "PhotonPort-usb-auth-salt-v1", [u64(3), text(macInstallID), text(deviceInstallID), text(purpose)], "PhotonPort-usb-auth-key-v1")
    }

    static func proof(_ type: String, key: SymmetricKey, macInstallID: String, deviceInstallID: String, purpose: String, macNonce: Data, deviceNonce: Data? = nil) -> Data? {
        guard ["usb-bind-init", "usb-bind-challenge", "usb-bind-finish", "usb-bind-accept"].contains(type), macNonce.count == 32,
              type == "usb-bind-init" ? deviceNonce == nil : deviceNonce?.count == 32 else { return nil }
        var fields = [text(type), u64(1), text(macInstallID), text(deviceInstallID), text(purpose), macNonce]
        if let deviceNonce { fields.append(deviceNonce) }
        return hmac(key, fields)
    }

    static func binding(psk: Data, macInstallID: String, deviceInstallID: String, purpose: String, macNonce: Data, deviceNonce: Data) -> Data? {
        guard valid(psk, macInstallID, deviceInstallID, purpose), macNonce.count == 32, deviceNonce.count == 32 else { return nil }
        return data(derive(psk, "PhotonPort-usb-binding-salt-v1", [u64(3), text(macInstallID), text(deviceInstallID), text(purpose), macNonce, deviceNonce], "PhotonPort-usb-binding-v1"))
    }

    static func recordKeys(binding: Data, macInstallID: String, deviceInstallID: String, purpose: String, macNonce: Data, deviceNonce: Data) -> (macToDevice: SymmetricKey, deviceToMac: SymmetricKey)? {
        guard valid(binding, macInstallID, deviceInstallID, purpose), macNonce.count == 32, deviceNonce.count == 32 else { return nil }
        let salt = Data(SHA256.hash(data: lp([text("PhotonPort-usb-record-salt-v1"), u64(3), u64(1), text(macInstallID), text(deviceInstallID), text(purpose), macNonce, deviceNonce])))
        let key = SymmetricKey(data: binding)
        return (HKDF<SHA256>.deriveKey(inputKeyMaterial: key, salt: salt, info: text("PhotonPort-usb-record-mac-to-device-v1"), outputByteCount: 32),
                HKDF<SHA256>.deriveKey(inputKeyMaterial: key, salt: salt, info: text("PhotonPort-usb-record-device-to-mac-v1"), outputByteCount: 32))
    }

    static func recordTag(key: SymmetricKey, macInstallID: String, deviceInstallID: String, purpose: String, direction: String, sequence: UInt64, payload: Data) -> Data? {
        guard ["mac-to-device", "device-to-mac"].contains(direction) else { return nil }
        return hmac(key, [text("PhotonPort-usb-record-v1"), u64(1), text(macInstallID), text(deviceInstallID), text(purpose), text(direction), u64(sequence), payload])
    }

    static func randomNonce() -> Data? { SessionCrypto.randomBytes(count: 32) }
    private static func valid(_ psk: Data, _ mac: String, _ device: String, _ purpose: String) -> Bool { psk.count == 32 && !mac.isEmpty && mac.utf8.count <= 256 && !device.isEmpty && device.utf8.count <= 256 && ["primary", "audio"].contains(purpose) }
    private static func derive(_ psk: Data, _ label: String, _ fields: [Data], _ info: String) -> SymmetricKey { HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: psk), salt: Data(SHA256.hash(data: lp([text(label)] + fields))), info: text(info), outputByteCount: 32) }
    private static func hmac(_ key: SymmetricKey, _ fields: [Data]) -> Data { Data(HMAC<SHA256>.authenticationCode(for: lp(fields), using: key)) }
    private static func lp(_ fields: [Data]) -> Data { SessionCrypto.lengthPrefixed(fields) }
    private static func text(_ value: String) -> Data { Data(value.utf8) }
    private static func u64(_ value: UInt64) -> Data { var value = value.bigEndian; return Data(bytes: &value, count: 8) }
    private static func data(_ key: SymmetricKey) -> Data { key.withUnsafeBytes { Data($0) } }
}

final class USBRecordState {
    private var sendKey: SymmetricKey?
    private var receiveKey: SymmetricKey?
    private let macInstallID: String, deviceInstallID: String, purpose: String
    private let sendDirection: String, receiveDirection: String
    private var sendSequence: UInt64 = 0, receiveSequence: UInt64 = 0
    private(set) var closed = false

    init?(role: String, binding: Data, macInstallID: String, deviceInstallID: String, purpose: String, macNonce: Data, deviceNonce: Data) {
        guard role == "mac" || role == "device",
              let keys = USBChannelCrypto.recordKeys(binding: binding, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, macNonce: macNonce, deviceNonce: deviceNonce) else { return nil }
        (sendKey, receiveKey, sendDirection, receiveDirection) = role == "mac" ? (keys.macToDevice, keys.deviceToMac, "mac-to-device", "device-to-mac") : (keys.deviceToMac, keys.macToDevice, "device-to-mac", "mac-to-device")
        self.macInstallID = macInstallID; self.deviceInstallID = deviceInstallID; self.purpose = purpose
    }

    func frame(_ payload: Data, cap: Int) -> Data? {
        guard !closed, !payload.isEmpty, cap > 0, payload.count <= cap, let sendKey,
              let tag = USBChannelCrypto.recordTag(key: sendKey, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, direction: sendDirection, sequence: sendSequence, payload: payload),
              sendSequence < UInt64.max else { clear(); return nil }
        var sequence = sendSequence.bigEndian; var body = Data(bytes: &sequence, count: 8); body += payload; body += tag; sendSequence += 1
        var length = UInt32(body.count).bigEndian; return Data(bytes: &length, count: 4) + body
    }

    func consume(_ data: Data, cap: Int) -> (Data, Data)? {
        guard !closed, cap > 0, data.count >= 4 else { clear(); return nil }
        let length = data.prefix(4).withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
        guard length > 40, length <= cap + 40, data.count >= 4 + Int(length), let receiveKey else { clear(); return nil }
        let body = data[4..<(4 + Int(length))], payload = Data(body.dropFirst(8).dropLast(32)), tag = Data(body.suffix(32))
        let sequence = body.prefix(8).withUnsafeBytes { UInt64(bigEndian: $0.loadUnaligned(as: UInt64.self)) }
        guard sequence == receiveSequence, receiveSequence < UInt64.max,
              let expected = USBChannelCrypto.recordTag(key: receiveKey, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, direction: receiveDirection, sequence: sequence, payload: payload),
              SessionCrypto.constantTimeEqual(tag, expected) else { clear(); return nil }
        receiveSequence += 1; return (payload, Data(data.dropFirst(4 + Int(length))))
    }

    func clear() { sendKey = nil; receiveKey = nil; sendSequence = 0; receiveSequence = 0; closed = true }
}

final class USBPrefaceClient {
    private let psk: Data, macInstallID: String, deviceInstallID: String, purpose: String, startedAt: TimeInterval, token: UInt64
    private var macNonce: Data?, deviceNonce: Data?, binding: Data?
    private var state = "idle"
    init?(psk: Data, macInstallID: String, deviceInstallID: String, purpose: String, startedAt: TimeInterval, token: UInt64, macNonce: Data? = nil) {
        guard USBChannelCrypto.authKey(psk: psk, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose) != nil else { return nil }
        self.psk = psk; self.macInstallID = macInstallID; self.deviceInstallID = deviceInstallID; self.purpose = purpose; self.startedAt = startedAt; self.token = token; self.macNonce = macNonce
    }
    func start(now: TimeInterval, token: UInt64, nonce: Data? = nil) -> Data? {
        guard active(now, token), state == "idle" else { clear(); return nil }
        macNonce = nonce ?? macNonce ?? USBChannelCrypto.randomNonce()
        guard let macNonce, macNonce.count == 32, let key = USBChannelCrypto.authKey(psk: psk, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose),
              let proof = USBChannelCrypto.proof("usb-bind-init", key: key, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, macNonce: macNonce),
              let frame = USBPrefaceMessage.frame(USBPrefaceMessage(type: "usb-bind-init", v: 1, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, macNonce: macNonce.base64EncodedString(), deviceNonce: nil, proof: proof.base64EncodedString())) else { clear(); return nil }
        state = "init-sent"; return USBPrefaceMessage.magic + frame
    }
    func consume(_ payload: Data, now: TimeInterval, token: UInt64) -> Data? {
        guard active(now, token), state == "init-sent" || state == "finish-sent" else { clear(); return nil }
        let expected = state == "init-sent" ? "usb-bind-challenge" : "usb-bind-accept"
        guard let message = USBPrefaceMessage.decode(payload, expectedType: expected), message.macInstallID == macInstallID, message.deviceInstallID == deviceInstallID, message.purpose == purpose,
              let mac = Data(base64Encoded: message.macNonce), mac == macNonce, let device = message.deviceNonce.flatMap({ Data(base64Encoded: $0) }),
              let proof = Data(base64Encoded: message.proof), let key = USBChannelCrypto.authKey(psk: psk, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose),
              let expectedProof = USBChannelCrypto.proof(expected, key: key, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, macNonce: mac, deviceNonce: device),
              (state == "init-sent" || device == deviceNonce),
              SessionCrypto.constantTimeEqual(proof, expectedProof) else { clear(); return nil }
        deviceNonce = device
        if expected == "usb-bind-accept" { binding = USBChannelCrypto.binding(psk: psk, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, macNonce: mac, deviceNonce: device); state = "authenticated"; return Data() }
        guard let finish = USBChannelCrypto.proof("usb-bind-finish", key: key, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, macNonce: mac, deviceNonce: device),
              let frame = USBPrefaceMessage.frame(USBPrefaceMessage(type: "usb-bind-finish", v: 1, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, macNonce: mac.base64EncodedString(), deviceNonce: device.base64EncodedString(), proof: finish.base64EncodedString())) else { clear(); return nil }
        state = "finish-sent"; return frame
    }
    func authenticatedBinding() -> Data? { state == "authenticated" ? binding : nil }
    func authenticatedContext() -> (binding: Data, macNonce: Data, deviceNonce: Data)? {
        guard state == "authenticated", let binding, let macNonce, let deviceNonce else { return nil }
        return (binding, macNonce, deviceNonce)
    }
    func clear() { macNonce = nil; deviceNonce = nil; binding = nil; state = "closed" }
    private func active(_ now: TimeInterval, _ token: UInt64) -> Bool { state != "closed" && token == self.token && now < startedAt + 5 }
}

final class USBPrefaceServer {
    private let psk: Data, macInstallID: String, deviceInstallID: String, purpose: String, startedAt: TimeInterval, token: UInt64
    private var macNonce: Data?, deviceNonce: Data?, binding: Data?
    private var state = "await-magic"
    init?(psk: Data, macInstallID: String, deviceInstallID: String, purpose: String, startedAt: TimeInterval, token: UInt64) {
        guard USBChannelCrypto.authKey(psk: psk, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose) != nil else { return nil }
        self.psk = psk; self.macInstallID = macInstallID; self.deviceInstallID = deviceInstallID; self.purpose = purpose; self.startedAt = startedAt; self.token = token
    }
    func consumeMagic(_ magic: Data, now: TimeInterval, token: UInt64) -> Bool { guard active(now, token), state == "await-magic", magic == USBPrefaceMessage.magic else { clear(); return false }; state = "await-init"; return true }
    func consume(_ payload: Data, now: TimeInterval, token: UInt64, nonce: Data? = nil) -> Data? {
        guard active(now, token), state == "await-init" || state == "challenge-sent" else { clear(); return nil }
        let expected = state == "await-init" ? "usb-bind-init" : "usb-bind-finish"
        guard let message = USBPrefaceMessage.decode(payload, expectedType: expected), message.macInstallID == macInstallID, message.deviceInstallID == deviceInstallID, message.purpose == purpose,
              let mac = Data(base64Encoded: message.macNonce), let proof = Data(base64Encoded: message.proof),
              let key = USBChannelCrypto.authKey(psk: psk, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose),
              let expectedProof = USBChannelCrypto.proof(expected, key: key, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, macNonce: mac, deviceNonce: expected == "usb-bind-init" ? nil : deviceNonce),
              (expected == "usb-bind-init" || message.deviceNonce.flatMap({ Data(base64Encoded: $0) }) == deviceNonce),
              SessionCrypto.constantTimeEqual(proof, expectedProof) else { clear(); return nil }
        macNonce = mac
        if expected == "usb-bind-finish" {
            guard let deviceNonce, let result = USBChannelCrypto.binding(psk: psk, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, macNonce: mac, deviceNonce: deviceNonce),
                  let accept = USBChannelCrypto.proof("usb-bind-accept", key: key, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, macNonce: mac, deviceNonce: deviceNonce),
                  let frame = USBPrefaceMessage.frame(USBPrefaceMessage(type: "usb-bind-accept", v: 1, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, macNonce: mac.base64EncodedString(), deviceNonce: deviceNonce.base64EncodedString(), proof: accept.base64EncodedString())) else { clear(); return nil }
            binding = result; state = "authenticated"; return frame
        }
        deviceNonce = nonce ?? USBChannelCrypto.randomNonce()
        guard let deviceNonce, deviceNonce.count == 32,
              let challenge = USBChannelCrypto.proof("usb-bind-challenge", key: key, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, macNonce: mac, deviceNonce: deviceNonce),
              let frame = USBPrefaceMessage.frame(USBPrefaceMessage(type: "usb-bind-challenge", v: 1, macInstallID: macInstallID, deviceInstallID: deviceInstallID, purpose: purpose, macNonce: mac.base64EncodedString(), deviceNonce: deviceNonce.base64EncodedString(), proof: challenge.base64EncodedString())) else { clear(); return nil }
        state = "challenge-sent"; return frame
    }
    func authenticatedBinding() -> Data? { state == "authenticated" ? binding : nil }
    func clear() { macNonce = nil; deviceNonce = nil; binding = nil; state = "closed" }
    private func active(_ now: TimeInterval, _ token: UInt64) -> Bool { state != "closed" && token == self.token && now < startedAt + 5 }
}
// MARK: - Framing (4-byte BE length + JSON payload)

enum PairingWire {
    static func frame<T: Encodable>(_ message: T, kind: ProtocolParser.FrameKind = .pairing) -> Data? {
        guard let payload = try? JSONEncoder().encode(message),
              (try? ProtocolParser.validatePayload(
                payload, expectedLength: payload.count, kind: kind)) != nil else {
            return nil
        }
        var header = UInt32(payload.count).bigEndian
        var data = Data(bytes: &header, count: 4)
        data.append(payload)
        return data
    }

    /// Reads exactly one framed JSON message.
    static func receive<T: Decodable & Sendable>(_ type: T.Type, on conn: NWConnection,
                                      completion: @escaping (T?) -> Void) {
        conn.receive(minimumIncompleteLength: 4, maximumLength: 4) { data, _, _, err in
            guard let data, data.count == 4, err == nil else { return completion(nil) }
            do {
                let len = try ProtocolParser.framedPayloadLength(from: data, kind: .pairing)
                conn.receive(minimumIncompleteLength: len, maximumLength: len) { payload, _, _, err in
                    guard let payload, err == nil,
                          (try? ProtocolParser.validatePayload(payload, expectedLength: len, kind: .pairing)) != nil,
                          let decoded = try? PairingWire.decode(type, from: payload) else {
                        return completion(nil)
                    }
                    completion(decoded)
                }
            } catch {
                completion(nil)
            }
        }
    }

    static func decode<T: Decodable & Sendable>(_ type: T.Type, from payload: Data) throws -> T {
        if type == PairCommit.self { return try ProtocolParser.parsePairCommit(payload) as! T }
        if type == PairHello.self { return try ProtocolParser.parsePairHello(payload) as! T }
        if type == SessionAccept.self { return try ProtocolParser.parseSessionAccept(payload) as! T }
        if type == SessionBusy.self { return try ProtocolParser.parseSessionBusy(payload) as! T }
        if type == SessionChannelOpen.self { return try ProtocolParser.parseChannelOpen(payload) as! T }
        throw ProtocolParser.ParseError.type
    }
}

/// Non-secret receiver identity index. It deliberately stores no credentials and
/// lets callers select one exact keychain account rather than probing candidates.
enum PairedReceiverIndex {
    private static let defaultsKey = "pairedReceiverInstallIDs"

    static var receiverIDs: [String] {
        Array(Set(UserDefaults.standard.stringArray(forKey: defaultsKey) ?? []))
            .filter { !$0.isEmpty && $0.utf8.count <= 256 }
            .sorted()
    }

    static func contains(_ receiverID: String) -> Bool { receiverIDs.contains(receiverID) }

    static func record(_ receiverID: String) {
        guard !receiverID.isEmpty, receiverID.utf8.count <= 256 else { return }
        var ids = Set(receiverIDs); ids.insert(receiverID)
        UserDefaults.standard.set(ids.sorted(), forKey: defaultsKey)
    }

    static func remove(_ receiverID: String) {
        var ids = Set(receiverIDs); ids.remove(receiverID)
        UserDefaults.standard.set(ids.sorted(), forKey: defaultsKey)
    }

    /// Resolves only the supplied identity; there is no multi-key fallback.
    static func lookup<T>(_ receiverID: String, using resolver: (String) -> T?) -> T? {
        guard contains(receiverID) else { return nil }
        return resolver(receiverID)
    }
}

// MARK: - Secret storage (Keychain)

/// Injectable Keychain calls used by `PairingStore`. Keeping all mutation
/// operations behind this seam lets storage failures be tested without touching
/// a user's Keychain.
struct PairingKeychainOperations {
    var copyMatching: ([String: Any]) -> (OSStatus, Data?)
    var update: ([String: Any], [String: Any]) -> OSStatus
    var add: ([String: Any]) -> OSStatus
    var delete: ([String: Any]) -> OSStatus

    static let live = PairingKeychainOperations(
        copyMatching: { query in
            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            return (status, result as? Data)
        },
        update: { query, attributes in
            SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        },
        add: { attributes in
            SecItemAdd(attributes as CFDictionary, nil)
        },
        delete: { query in
            SecItemDelete(query as CFDictionary)
        })
}

enum PairingStore {
    private static let keychainService = "dev.hyupji.photonport.pairing"
    /// Internal test seam. Production always starts with the live Security
    /// implementation; tests must restore it after replacement.
    static var keychainOperations = PairingKeychainOperations.live

    /// The Mac's stable identity — sent in pair-start and used as the
    /// TLS-PSK identity hint so the receiver picks the right key.
    static var macInstallID: String {
        if let existing = UserDefaults.standard.string(forKey: "pairingInstallID") {
            return existing
        }
        let fresh = UUID().uuidString
        UserDefaults.standard.set(fresh, forKey: "pairingInstallID")
        return fresh
    }

    // macOS uses the default (file) keychain here: the data-protection
    // keychain (kSecUseDataProtectionKeychain) requires an app-identifier /
    // keychain-access-group entitlement this dev/unsigned build doesn't
    // carry, and requesting it returns errSecMissingEntitlement (-34018),
    // which was silently blocking pairing from saving its key. The file
    // keychain still honors Synchronizable=false; kSecAttrAccessible is a
    // data-protection attribute and is simply ignored here (harmless).
    private static func baseQuery(_ deviceID: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: deviceID,
            kSecAttrSynchronizable as String: false,
        ]
    }

    static func psk(for deviceID: String) -> Data? {
        var query = baseQuery(deviceID)
        query[kSecReturnData as String] = true
        // Never let a keychain ACL prompt block this read: it runs during
        // menu-bar popover rendering, and the prompt stealing key focus
        // dismisses the popover. A foreign item (e.g. written by a build with
        // a different code signature) reads as "not paired"; re-pairing then
        // reports storage failure rather than risking deletion of that key.
        let context = LAContext()
        context.interactionNotAllowed = true
        query[kSecUseAuthenticationContext as String] = context
        let (status, data) = keychainOperations.copyMatching(query)
        guard status == errSecSuccess else {
            return nil
        }
        return data
    }

    /// Returns false if the key could not be stored — callers MUST NOT treat
    /// the device as paired on failure.
    @discardableResult
    static func setPSK(_ psk: Data, for deviceID: String) -> Bool {
        let base = baseQuery(deviceID)
        let attrs: [String: Any] = [
            kSecValueData as String: psk,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]

        // Updating an existing Keychain item is atomic. In particular, do not
        // delete-and-add after an update error: that sequence can destroy a
        // credential that is still usable when either operation fails.
        let updateStatus = keychainOperations.update(base, attrs)
        if updateStatus == errSecSuccess {
            PairedReceiverIndex.record(deviceID)
            return true
        }
        guard updateStatus == errSecItemNotFound else {
            Log.info("pairing: keychain update failed (\(updateStatus)); existing key retained")
            return false
        }

        var add = base
        add.merge(attrs) { _, new in new }
        let addStatus = keychainOperations.add(add)
        if addStatus != errSecSuccess {
            Log.info("pairing: keychain add failed (\(addStatus))")
        }
        if addStatus == errSecSuccess { PairedReceiverIndex.record(deviceID) }
        return addStatus == errSecSuccess
    }

    /// Removes a stored credential. A missing item is already unpaired; all
    /// other Keychain errors are reported to prevent false-success state.
    @discardableResult
    static func removePSK(for deviceID: String) -> Bool {
        let status = keychainOperations.delete(baseQuery(deviceID))
        guard status == errSecSuccess || status == errSecItemNotFound else {
            Log.info("pairing: keychain delete failed (\(status))")
            return false
        }
        PairedReceiverIndex.remove(deviceID)
        return true
    }
}

// MARK: - Client (drives one pairing exchange)

enum PairingError: LocalizedError {
    case serviceNotFound     // receiver's pairing screen isn't open
    case permissionDenied    // Mac lacks Local Network permission (NoAuth)
    case protocolError
    case rejected(String)    // receiver refused, or the user cancelled

    var errorDescription: String? {
        switch self {
        case .serviceNotFound:
            return "Pairing service not found — on the device, open Settings → Pair a Mac and keep that screen up, then try again."
        case .permissionDenied:
            return "PhotonPort needs Local Network access. In System Settings → Privacy & Security → Local Network, enable \"PhotonPort Dev\" (or PhotonPort). If it's already on, toggle it off and back on so the new pairing service is authorized, then try again."
        case .protocolError:
            return "Pairing failed — connection error."
        case .rejected(let reason):
            return reason
        }
    }
}

enum PairingClient {
    /// Finds the device's pairing service (its video service type carrying a
    /// `pair=1` TXT flag, matched by install id), runs the exchange, and
    /// returns the receiver's identity + derived PSK. The caller persists
    /// the PSK; this function has no storage side effects.
    static func pair(targetID: String, macName: String, macInstallID: String)
        async throws -> (deviceID: String, sas: String, psk: Data) {
        let endpoint = try await discover(targetID: targetID)
        return try await exchange(endpoint: endpoint, macName: macName,
                                  macInstallID: macInstallID, targetID: targetID)
    }

    /// Browses the video service type for a `pair=1` instance whose `id`
    /// matches the target device. That instance only exists while the
    /// device's pairing screen is open.
    static func discover(targetID: String,
                         timeout: TimeInterval = 10) async throws -> NWEndpoint {
        Log.info("pairing/discover: browsing \(PairingCrypto.serviceType) for pair=1 id=\(targetID.prefix(8))")
        let browser = NWBrowser(for: .bonjourWithTXTRecord(type: PairingCrypto.serviceType, domain: nil),
                                using: .tcp)
        // Single continuation with a resume-once gate and a scheduled timeout.
        // (A task group here would hang: if the browser goes ready but never
        // matches, the timeout child throws while the browser child's
        // continuation is never resumed, and the group awaits all children.)
        return try await withCheckedThrowingContinuation { cont in
            let done = ContinuationGate()
            @discardableResult
            @Sendable func finish(_ result: Result<NWEndpoint, Error>) -> Bool {
                guard done.claim() else { return false }
                browser.cancel()
                cont.resume(with: result)
                return true
            }
            browser.browseResultsChangedHandler = { results, _ in
                for result in results {
                    guard case .bonjour(let txt) = result.metadata,
                          txt[PairingCrypto.pairTXTKey] == "1",
                          txt["id"] == targetID else { continue }
                    Log.info("pairing/discover: matched pairing instance for \(targetID.prefix(8))")
                    finish(.success(result.endpoint))
                    return
                }
            }
            browser.stateUpdateHandler = { state in
                switch state {
                case .failed(let error):
                    Log.info("pairing/discover: browser FAILED: \(error)")
                    // -65555 = kDNSServiceErr_NoAuth: no Local Network
                    // authorization — distinct guidance from "not advertised".
                    let denied: Bool
                    if case .dns(let code) = error, code == -65555 { denied = true }
                    else { denied = false }
                    finish(.failure(denied ? PairingError.permissionDenied
                                           : PairingError.serviceNotFound))
                case .waiting(let error):
                    Log.info("pairing/discover: browser waiting: \(error)")
                case .ready:
                    Log.info("pairing/discover: browser ready")
                default:
                    break
                }
            }
            browser.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                if finish(.failure(PairingError.serviceNotFound)) {
                    Log.info("pairing/discover: timed out after \(Int(timeout))s")
                }
            }
        }
    }

    /// Swaps one PairHello each way, derives the SAS + PSK, and returns them.
    /// No PIN is sent; the caller displays the SAS for the user to compare
    /// against the device's screen and only stores the PSK on confirmation.
    static func exchange(endpoint: NWEndpoint, macName: String,
                         macInstallID: String, targetID: String)
        async throws -> (deviceID: String, sas: String, psk: Data) {
        let key = Curve25519.KeyAgreement.PrivateKey()
        guard let macNonce = PairingCrypto.randomNonce() else { throw PairingError.protocolError }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let conn = NWConnection(to: endpoint, using: NWParameters(tls: nil, tcp: tcp))
        defer { conn.cancel() }

        return try await withCheckedThrowingContinuation { cont in
            let done = ContinuationGate()
            @Sendable func fail(_ error: PairingError) {
                if done.claim() { cont.resume(throwing: error) }
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    let macPub = key.publicKey.rawRepresentation
                    let macCommit = PairingCrypto.commitment(
                        role: "mac", installID: macInstallID, name: macName,
                        pub: macPub, nonce: macNonce)
                    guard let commitFrame = PairingWire.frame(
                        PairCommit(v: PairingCrypto.version,
                                   commit: macCommit.base64EncodedString()))
                    else { return fail(.protocolError) }
                    conn.send(content: commitFrame, completion: .contentProcessed { _ in })
                    // Receive the device's commitment BEFORE revealing our
                    // opening — this ordering is what stops SAS grinding.
                    PairingWire.receive(PairCommit.self, on: conn) { dc in
                        guard let dc, dc.v == PairingCrypto.version,
                              let deviceCommit = Data(base64Encoded: dc.commit),
                              deviceCommit.count == 32
                        else { return fail(.protocolError) }
                        let hello = PairHello(
                            v: PairingCrypto.version, role: "mac",
                            installID: macInstallID, name: macName,
                            pub: macPub.base64EncodedString(),
                            nonce: macNonce.base64EncodedString())
                        guard let frame = PairingWire.frame(hello) else { return fail(.protocolError) }
                        conn.send(content: frame, completion: .contentProcessed { _ in })
                        PairingWire.receive(PairHello.self, on: conn) { peer in
                            guard let peer, peer.v == PairingCrypto.version, peer.role == "device",
                                  let devicePub = Data(base64Encoded: peer.pub), devicePub.count == 32,
                                  let deviceNonce = Data(base64Encoded: peer.nonce), deviceNonce.count == 16,
                                  let deviceKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: devicePub),
                                  let shared = try? key.sharedSecretFromKeyAgreement(with: deviceKey)
                            else { return fail(.protocolError) }
                            // The reveal must hash back to the earlier commit,
                            // else the peer swapped keys after committing.
                            let expect = PairingCrypto.commitment(
                                role: "device", installID: peer.installID, name: peer.name,
                                pub: devicePub, nonce: deviceNonce)
                            guard SessionCrypto.constantTimeEqual(expect, deviceCommit) else {
                                return fail(.rejected("Pairing failed — the device's commitment did not match (possible tampering on the network)."))
                            }
                            // The receiver must be the device we targeted.
                            guard peer.installID == targetID else {
                                return fail(.rejected("Pairing failed — the device identity did not match."))
                            }
                            let tr = PairingCrypto.transcript(
                                macInstallID: macInstallID, deviceInstallID: peer.installID,
                                macPub: macPub, devicePub: devicePub,
                                macNonce: macNonce, deviceNonce: deviceNonce)
                            let sas = PairingCrypto.sasDigits(shared: shared, transcript: tr)
                            let psk = PairingCrypto.psk(shared: shared, transcript: tr)
                            if done.claim() { cont.resume(returning: (peer.installID, sas, psk)) }
                        }
                    }
                case .failed, .cancelled:
                    fail(.protocolError)
                default:
                    break
                }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 15) {
                fail(.protocolError)
            }
        }
    }
}

/// Tiny thread-safe "resume exactly once" latch for continuation-based flows.
final class ContinuationGate {
    private let lock = NSLock()
    private var claimed = false
    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if claimed { return false }
        claimed = true
        return true
    }
}
// MARK: - Authoritative Mac protocol consumers
//
// These results are returned only after a receiving boundary rejects its input.
struct MacProtocolConsumerResult: Equatable, Sendable {
    let vector: String
    let mutation: String
    let stage: String
    let outcome: String

    static func rejected(_ vector: String, mutation: String,
                         stage: String) -> MacProtocolConsumerResult {
        MacProtocolConsumerResult(
            vector: vector, mutation: mutation, stage: stage, outcome: "rejected"
        )
    }
}

enum MacProtocolConsumers {
    static func sessionInitResponse(_ payload: Data, transport: ProtocolParser.Transport,
                                    expectedDeviceNonce: Data? = nil, vector: String,
                                    mutation: String) -> MacProtocolConsumerResult? {
        guard let hello = try? ProtocolParser.parseServerHello(payload, transport: transport),
              expectedDeviceNonce == nil || hello.deviceNonce == expectedDeviceNonce else {
            return .rejected(vector, mutation: mutation, stage: "session-init-response")
        }
        return nil
    }

    static func sessionFinishAccept(_ payload: Data, primaryKey: SymmetricKey,
                                    macInstallID: String, deviceInstallID: String,
                                    macNonce: Data, deviceNonce: Data,
                                    vector: String, mutation: String,
                                    stage: String = "session-finish-accept") -> MacProtocolConsumerResult? {
        guard (try? ProtocolParser.parseVerifiedSessionAccept(
            payload, primaryKey: primaryKey, macInstallID: macInstallID,
            deviceInstallID: deviceInstallID, macNonce: macNonce,
            deviceNonce: deviceNonce)) != nil else {
            return .rejected(vector, mutation: mutation, stage: stage)
        }
        return nil
    }

    static func sessionBusyResponse(_ payload: Data, vector: String,
                                    mutation: String) -> MacProtocolConsumerResult? {
        guard (try? ProtocolParser.parseSessionBusy(payload)) != nil else {
            return .rejected(vector, mutation: mutation, stage: "session-busy-response")
        }
        return nil
    }

    static func mediaInbound(annexB: Data, keyframe: Bool, codec: String,
                             vector: String, mutation: String) -> MacProtocolConsumerResult? {
        let startCode = Data([0, 0, 0, 1])
        let hasH264Parameters = annexB.contains(startCode + Data([0x67])) &&
            annexB.contains(startCode + Data([0x68]))
        let hasHEVCParameters = annexB.contains(startCode + Data([0x40])) &&
            annexB.contains(startCode + Data([0x42])) &&
            annexB.contains(startCode + Data([0x44]))
        let h264RandomAccess = annexB.contains(startCode + Data([0x65]))
        let hevcRandomAccess = annexB.contains(startCode + Data([0x26]))
        let valid = codec == "h264"
            ? (!h264RandomAccess || keyframe && hasH264Parameters)
            : (!hevcRandomAccess || keyframe && hasHEVCParameters)
        return valid ? nil : .rejected(vector, mutation: mutation, stage: "media-inbound")
    }

}

/// Mac-side candidate wrapper. It exposes direction-specific receive methods so
/// a server challenge can never be accepted in the accept state, and vice versa.
final class USBChannelCandidate {
    private let client: USBPrefaceClient

    init?(psk: Data, macInstallID: String, deviceInstallID: String, purpose: String,
          startedAt: TimeInterval, token: UInt64, macNonce: Data) {
        guard let client = USBPrefaceClient(
            psk: psk, macInstallID: macInstallID, deviceInstallID: deviceInstallID,
            purpose: purpose, startedAt: startedAt, token: token, macNonce: macNonce
        ) else { return nil }
        self.client = client
    }

    func start(now: TimeInterval, token: UInt64) -> Data? {
        client.start(now: now, token: token)
    }

    func receiveChallenge(_ payload: Data, now: TimeInterval, token: UInt64,
                          vector: String, mutation: String) -> MacProtocolConsumerResult? {
        guard client.consume(payload, now: now, token: token) != nil else {
            return .rejected(vector, mutation: mutation, stage: "usb-bind-challenge")
        }
        return nil
    }

    func receiveAccept(_ payload: Data, now: TimeInterval, token: UInt64,
                       vector: String, mutation: String) -> MacProtocolConsumerResult? {
        guard client.consume(payload, now: now, token: token) != nil else {
            return .rejected(vector, mutation: mutation, stage: "usb-bind-accept")
        }
        return nil
    }
}
