// SPDX-License-Identifier: GPL-3.0-only
// Part of PhotonPort, a GPL-3.0 fork of OpenDisplay
// (https://github.com/peetzweg/opendisplay, (c) peetzweg and contributors).
// This file (c) 2026 hyupji, added in the fork.

// Pairing (receiver side) — see Mac/Pairing.swift for the protocol and
// threat model. This file is deliberately UIKit-free (Foundation/Network/
// CryptoKit only) so the pairing exchange can be exercised on a Mac in a
// CLI harness against the real Mac-side client code.

import Foundation
import Network
import CryptoKit

// MARK: - Wire messages (mirror of Mac/Pairing.swift)

struct PairHello: Codable {
    var type = "pair-hello"
    let v: Int
    let role: String        // "mac" | "device"
    let installID: String
    let name: String?
    let pub: String
    let nonce: String
}

// Hash commitment to an opening, exchanged before the opening is revealed.
struct PairCommit: Codable {
    var type = "pair-commit"
    let v: Int
    let commit: String
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
    // Pairing reuses the already-authorized video service type instead of a
    // dedicated one: macOS/iOS grant Local Network access per declared
    // service type, so a separate _photonport-pair._tcp would need its own
    // authorization (and silently NoAuth's until granted). The pairing
    // listener advertises _photonport._tcp with a `pair=1` TXT flag; the
    // Mac matches on that flag + the install id.
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

    /// Hash commitment over an opening (role, install id, name, pub, nonce),
    /// exchanged before the opening is revealed so neither side can grind the
    /// SAS after seeing the peer's keys. Mirror of Mac/Pairing.swift.
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

    /// Length-prefixed, role-ordered transcript (client = Mac, server =
    /// device). Bonjour service name is excluded (user-editable + may be
    /// uniquified, which would desync the two transcripts).
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

    static func sasDigits(shared: SharedSecret, transcript: Data) -> String {
        let k = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: transcript,
            sharedInfo: Data("photonport-pair-sas-v2".utf8), outputByteCount: 4)
        let bytes = k.withUnsafeBytes { Array($0) }
        let v = (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16)
              | (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
        return String(format: "%06u", v % 1_000_000)
    }

    static func psk(shared: SharedSecret, transcript: Data) -> Data {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: transcript,
            sharedInfo: Data("photonport-pair-psk-v2".utf8), outputByteCount: 32)
            .withUnsafeBytes { Data($0) }
    }

    /// Server-side TLS-PSK options carrying every paired Mac's key; the TLS
    /// stack selects by the identity hint the client sends. nil when no Mac
    /// is paired yet (the secure listener still runs; handshakes just fail).
    static func serverTLSOptions(peers: [(identity: String, psk: Data)]) -> NWProtocolTLS.Options {
        let opts = NWProtocolTLS.Options()
        for peer in peers {
            addPSK(opts, identity: peer.identity, psk: peer.psk)
        }
        sec_protocol_options_append_tls_ciphersuite(
            opts.securityProtocolOptions,
            tls_ciphersuite_t(rawValue: UInt16(TLS_PSK_WITH_AES_128_GCM_SHA256))!)
        sec_protocol_options_set_min_tls_protocol_version(opts.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_max_tls_protocol_version(opts.securityProtocolOptions, .TLSv12)
        return opts
    }

    static func addPSK(_ opts: NWProtocolTLS.Options, identity: String, psk: Data) {
        let pskDD = psk.withUnsafeBytes { DispatchData(bytes: $0) }
        let idDD = Data(identity.utf8).withUnsafeBytes { DispatchData(bytes: $0) }
        sec_protocol_options_add_pre_shared_key(opts.securityProtocolOptions,
                                                pskDD as __DispatchData,
                                                idDD as __DispatchData)
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

// MARK: - Framing

enum PairingWire {
    static func frame<T: Encodable>(_ message: T) -> Data? {
        guard let payload = try? JSONEncoder().encode(message) else { return nil }
        var header = UInt32(payload.count).bigEndian
        var data = Data(bytes: &header, count: 4)
        data.append(payload)
        return data
    }

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

// MARK: - Paired-Mac storage (Keychain + UserDefaults name index)

/// PSKs live in the Keychain; a UserDefaults index carries the Mac names so
/// the Settings list renders without touching secrets.
enum PairingStore {
    private static let keychainService = "dev.hyupji.photonport.pairing"
    private static let indexKey = "pairedMacs"   // [installID: name]

    static var pairedMacs: [(id: String, name: String)] {
        let index = UserDefaults.standard.dictionary(forKey: indexKey) as? [String: String] ?? [:]
        return index.map { (id: $0.key, name: $0.value) }.sorted { $0.name < $1.name }
    }

    static func peers() -> [(identity: String, psk: Data)] {
        pairedMacs.compactMap { mac in
            psk(for: mac.id).map { (identity: mac.id, psk: $0) }
        }
    }

    /// Returns false if the key could not be stored — the index (which drives
    /// the "paired" list + the TLS PSK set) is only updated on success.
    @discardableResult
    static func add(macID: String, name: String, psk: Data) -> Bool {
        guard setPSK(psk, for: macID) else { return false }
        var index = UserDefaults.standard.dictionary(forKey: indexKey) as? [String: String] ?? [:]
        index[macID] = name
        UserDefaults.standard.set(index, forKey: indexKey)
        return true
    }

    static func remove(macID: String) {
        removePSK(for: macID)
        var index = UserDefaults.standard.dictionary(forKey: indexKey) as? [String: String] ?? [:]
        index.removeValue(forKey: macID)
        UserDefaults.standard.set(index, forKey: indexKey)
    }

    static func psk(for macID: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: macID,
            kSecReturnData as String: true,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else {
            return nil
        }
        return result as? Data
    }

    @discardableResult
    private static func setPSK(_ psk: Data, for macID: String) -> Bool {
        // Non-migrating, device-only: a long-term network auth key must not
        // sync to other devices or iCloud Keychain.
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: macID,
            kSecAttrSynchronizable as String: false,
        ]
        let attrs: [String: Any] = [
            kSecValueData as String: psk,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        // Update-in-place when present so a failed add can't lose an existing
        // PSK; only add (with the accessibility policy) when absent.
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

    private static func removePSK(for macID: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: macID,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - Server (runs only while the pairing screen is open)

/// One-shot pairing listener: ephemeral port, advertised over the video
/// service type with a `pair=1` TXT flag while the pairing screen is open.
/// It swaps one PairHello with the Mac, derives the SAS + PSK, and hands the
/// SAS to the UI. Nothing is stored until the user confirms the code matches
/// the Mac's screen (that human comparison is the authentication).
final class PairingServer {
    private let serviceName: String
    private let onSAS: (_ sas: String) -> Void
    private let onPaired: (_ macID: String, _ macName: String, _ psk: Data) -> Void
    private let queue = DispatchQueue(label: "pairing.server")
    private var listener: NWListener?
    private var active: NWConnection?
    private var pending: (macID: String, macName: String, psk: Data)?

    init(serviceName: String,
         onSAS: @escaping (_ sas: String) -> Void,
         onPaired: @escaping (_ macID: String, _ macName: String, _ psk: Data) -> Void) {
        self.serviceName = serviceName
        self.onSAS = onSAS
        self.onPaired = onPaired
    }

    func start() { queue.async { self.startListener() } }

    func stop() {
        queue.async {
            self.active?.cancel(); self.active = nil
            self.listener?.cancel(); self.listener = nil
            self.pending = nil
        }
    }

    /// The user confirmed the on-screen code matches the Mac's — store the PSK.
    func confirm() {
        queue.async {
            guard let p = self.pending else { return }
            self.pending = nil
            Log.info("pairing: user confirmed SAS — storing key for \"\(p.macName)\"")
            self.onPaired(p.macID, p.macName, p.psk)
            self.listener?.cancel(); self.listener = nil   // single-use
        }
    }

    private func startListener() {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let params = NWParameters(tls: nil, tcp: tcp)
        params.allowLocalEndpointReuse = true
        guard let listener = try? NWListener(using: params) else {   // ephemeral port
            Log.info("pairing: listener failed to start")
            return
        }
        var txt = NWTXTRecord()
        txt[PairingCrypto.pairTXTKey] = "1"
        txt["id"] = PhoneReceiverInstallID.value
        listener.service = NWListener.Service(name: serviceName,
                                              type: PairingCrypto.serviceType,
                                              domain: nil, txtRecord: txt)
        listener.newConnectionHandler = { [weak self] conn in
            guard let self else { return }
            self.active?.cancel()   // one attempt at a time
            self.active = conn
            conn.start(queue: self.queue)
            self.handle(conn)
        }
        listener.start(queue: queue)
        self.listener = listener
        Log.info("pairing: advertising \(PairingCrypto.serviceType) (pair=1) as \"\(serviceName)\"")
    }

    private func handle(_ conn: NWConnection) {
        let serverKey = Curve25519.KeyAgreement.PrivateKey()
        guard let deviceNonce = PairingCrypto.randomNonce() else {
            Log.info("pairing: nonce RNG failed — aborting")
            conn.cancel(); return
        }
        let devicePub = serverKey.publicKey.rawRepresentation
        let deviceCommit = PairingCrypto.commitment(
            role: "device", installID: PhoneReceiverInstallID.value, name: nil,
            pub: devicePub, nonce: deviceNonce)
        // Receive the Mac's commitment first, then send ours; only after both
        // are locked in does either side reveal its opening — the ordering
        // that stops an active MITM from grinding the SAS.
        PairingWire.receive(PairCommit.self, on: conn) { [weak self] mc in
            guard let self, conn === self.active else { return }
            guard let mc, mc.v == PairingCrypto.version,
                  let macCommit = Data(base64Encoded: mc.commit), macCommit.count == 32
            else { conn.cancel(); return }
            if let cf = PairingWire.frame(PairCommit(v: PairingCrypto.version,
                                                     commit: deviceCommit.base64EncodedString())) {
                conn.send(content: cf, completion: .contentProcessed { _ in })
            }
            PairingWire.receive(PairHello.self, on: conn) { [weak self] peer in
                guard let self, conn === self.active else { return }
                guard let peer, peer.v == PairingCrypto.version, peer.role == "mac",
                      let macPub = Data(base64Encoded: peer.pub), macPub.count == 32,
                      let macNonce = Data(base64Encoded: peer.nonce), macNonce.count == 16,
                      let macKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: macPub),
                      let shared = try? serverKey.sharedSecretFromKeyAgreement(with: macKey)
                else { conn.cancel(); return }
                // The Mac's reveal must hash back to its earlier commit.
                let expect = PairingCrypto.commitment(
                    role: "mac", installID: peer.installID, name: peer.name,
                    pub: macPub, nonce: macNonce)
                guard expect == macCommit else {
                    Log.info("pairing: commitment mismatch — aborting (possible tampering)")
                    conn.cancel(); return
                }
                let hello = PairHello(
                    v: PairingCrypto.version, role: "device",
                    installID: PhoneReceiverInstallID.value, name: nil,
                    pub: devicePub.base64EncodedString(),
                    nonce: deviceNonce.base64EncodedString())
                if let frame = PairingWire.frame(hello) {
                    conn.send(content: frame, completion: .contentProcessed { _ in })
                }
                let tr = PairingCrypto.transcript(
                    macInstallID: peer.installID, deviceInstallID: PhoneReceiverInstallID.value,
                    macPub: macPub, devicePub: devicePub,
                    macNonce: macNonce, deviceNonce: deviceNonce)
                let sas = PairingCrypto.sasDigits(shared: shared, transcript: tr)
                let psk = PairingCrypto.psk(shared: shared, transcript: tr)
                self.pending = (macID: peer.installID, macName: peer.name ?? "Mac", psk: psk)
                Log.info("pairing: SAS ready for \"\(peer.name ?? "Mac")\"")
                self.onSAS(sas)
            }
        }
    }
}

/// The receiver's install id without importing PhoneReceiver (which pulls
/// UIKit and would break the CLI pairing harness). Same UserDefaults key —
/// one identity per install.
enum PhoneReceiverInstallID {
    static var value: String {
        if let existing = UserDefaults.standard.string(forKey: "installID") {
            return existing
        }
        let fresh = UUID().uuidString
        UserDefaults.standard.set(fresh, forKey: "installID")
        return fresh
    }
}
