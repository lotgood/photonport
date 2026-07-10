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

// MARK: - Wire messages

// Two message types flow in both directions. First a PairCommit (a hash of
// the opening below) is exchanged; only then is the PairHello opening revealed
// and checked against the peer's earlier commit. No low-entropy secret (PIN)
// is ever transmitted — authentication is the human comparing the derived SAS
// on both screens, which the commitment phase makes ungrindable.
struct PairHello: Codable {
    var type = "pair-hello"
    let v: Int              // protocol version (2)
    let role: String        // "mac" | "device"
    let installID: String
    let name: String?       // Mac's user-visible name (device omits)
    let pub: String         // X25519 public key, base64
    let nonce: String       // 16 random bytes, base64
}

// Hash commitment to an opening, exchanged before the opening is revealed.
struct PairCommit: Codable {
    var type = "pair-commit"
    let v: Int
    let commit: String      // base64 of the 32-byte SHA-256 commitment
}

// MARK: - Stream session v3 messages

struct SessionOpen: Codable {
    var type = "session-open"
    let v: Int
    let macInstallID: String
    let deviceInstallID: String
    let macNonce: String
    let primaryProof: String
}

struct SessionAccept: Codable {
    var type = "session-accept"
    let v: Int
    let sessionID: String
    let generation: UInt64
    let acceptProof: String
}

struct SessionBusy: Codable {
    var type = "session-busy"
    let v: Int
    let reason: String
}

struct SessionChannelOpen: Codable {
    var type = "channel-open"
    let v: Int
    let macInstallID: String
    let sessionID: String
    let generation: UInt64
    let channel: String
    let nonce: String
    let proof: String
}

/// Receiver-wide ownership and replay state for one primary stream session.
/// Keeping this reducer independent from Network.framework makes the busy,
/// stale-generation, and channel-replay rules deterministic to test.
struct SessionOwnershipState {
    struct Lease: Equatable {
        let macInstallID: String
        let generation: UInt64
    }

    enum Claim: Equatable {
        case accepted(Lease)
        case busy(Lease)
    }

    private(set) var generation: UInt64 = 0
    private(set) var active: Lease?
    private var channelNonces: Set<String> = []

    mutating func claim(macInstallID: String) -> Claim {
        if let active { return .busy(active) }
        generation &+= 1
        if generation == 0 { generation = 1 }
        let lease = Lease(macInstallID: macInstallID, generation: generation)
        active = lease
        channelNonces.removeAll(keepingCapacity: true)
        return .accepted(lease)
    }

    func authorizes(macInstallID: String, generation: UInt64) -> Bool {
        active == Lease(macInstallID: macInstallID, generation: generation)
    }

    mutating func consumeChannelNonce(macInstallID: String, generation: UInt64,
                                      nonce: Data) -> Bool {
        guard authorizes(macInstallID: macInstallID, generation: generation) else {
            return false
        }
        return channelNonces.insert(nonce.base64EncodedString()).inserted
    }

    @discardableResult
    mutating func release(macInstallID: String, generation: UInt64) -> Bool {
        guard authorizes(macInstallID: macInstallID, generation: generation) else {
            return false
        }
        active = nil
        channelNonces.removeAll(keepingCapacity: true)
        return true
    }
}

enum SessionTiming {
    static let receiverOwnershipTimeout: TimeInterval = 5
    static let macDisconnectGrace: TimeInterval = 10
    static let audioBeforePrimaryPending: TimeInterval = 2
    static let handshakeTimeout: TimeInterval = 5
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
    /// (verified against a live listener on macOS 26).
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

// MARK: - Framing (4-byte BE length + JSON payload)

enum PairingWire {
    static func frame<T: Encodable>(_ message: T) -> Data? {
        guard let payload = try? JSONEncoder().encode(message) else { return nil }
        var header = UInt32(payload.count).bigEndian
        var data = Data(bytes: &header, count: 4)
        data.append(payload)
        return data
    }

    /// Reads exactly one framed JSON message.
    static func receive<T: Decodable>(_ type: T.Type, on conn: NWConnection,
                                      completion: @escaping (T?) -> Void) {
        conn.receive(minimumIncompleteLength: 4, maximumLength: 4) { data, _, _, err in
            guard let data, data.count == 4, err == nil else { return completion(nil) }
            let len = Int(UInt32(bigEndian: data.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }))
            guard len > 0, len < 64 * 1024 else { return completion(nil) }
            conn.receive(minimumIncompleteLength: len, maximumLength: len) { payload, _, _, err in
                guard let payload, payload.count == len, err == nil else { return completion(nil) }
                completion(try? JSONDecoder().decode(T.self, from: payload))
            }
        }
    }
}

// MARK: - Secret storage (Keychain)

enum PairingStore {
    private static let keychainService = "dev.hyupji.photonport.pairing"

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
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else {
            return nil
        }
        return result as? Data
    }

    /// Returns false if the key could not be stored — callers MUST NOT treat
    /// the device as paired on failure.
    @discardableResult
    static func setPSK(_ psk: Data, for deviceID: String) -> Bool {
        let base = baseQuery(deviceID)
        // Update-in-place when present so a failed add can't lose an existing
        // PSK; only add (with the accessibility policy) when absent.
        let attrs: [String: Any] = [
            kSecValueData as String: psk,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(base as CFDictionary, attrs as CFDictionary)
        if updateStatus == errSecSuccess { return true }
        if updateStatus == errSecItemNotFound {
            var add = base
            add.merge(attrs) { _, new in new }
            let addStatus = SecItemAdd(add as CFDictionary, nil)
            if addStatus != errSecSuccess {
                Log.info("pairing: keychain add failed (\(addStatus))")
            }
            return addStatus == errSecSuccess
        }
        Log.info("pairing: keychain update failed (\(updateStatus))")
        return false
    }

    static func removePSK(for deviceID: String) {
        SecItemDelete(baseQuery(deviceID) as CFDictionary)
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
                            guard expect == deviceCommit else {
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
