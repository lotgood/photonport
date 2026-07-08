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

struct PairStart: Codable {
    var type = "pair-start"
    let name: String
    let installID: String
    let pub: String
}

struct PairChallenge: Codable {
    var type = "pair-challenge"
    let pub: String
    let salt: String
}

struct PairProof: Codable {
    var type = "pair-proof"
    let proof: String
}

struct PairResult: Codable {
    var type: String
    var deviceID: String?
    var reason: String?
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

    static func confirmKey(shared: SharedSecret, salt: Data) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                                       sharedInfo: Data("photonport-pair-confirm".utf8),
                                       outputByteCount: 32)
    }

    static func psk(shared: SharedSecret, salt: Data) -> Data {
        shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                                       sharedInfo: Data("photonport-pair-psk".utf8),
                                       outputByteCount: 32)
            .withUnsafeBytes { Data($0) }
    }

    static func proof(confirmKey: SymmetricKey, pin: String,
                      clientPub: Data, serverPub: Data) -> Data {
        var msg = Data(pin.utf8)
        msg.append(clientPub)
        msg.append(serverPub)
        return Data(HMAC<SHA256>.authenticationCode(for: msg, using: confirmKey))
    }

    static func validProof(_ proof: Data, confirmKey: SymmetricKey, pin: String,
                           clientPub: Data, serverPub: Data) -> Bool {
        var msg = Data(pin.utf8)
        msg.append(clientPub)
        msg.append(serverPub)
        return HMAC<SHA256>.isValidAuthenticationCode(proof, authenticating: msg,
                                                      using: confirmKey)
    }

    static func makePIN() -> String {
        String(format: "%06d", Int.random(in: 0...999_999))
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

    static func add(macID: String, name: String, psk: Data) {
        setPSK(psk, for: macID)
        var index = UserDefaults.standard.dictionary(forKey: indexKey) as? [String: String] ?? [:]
        index[macID] = name
        UserDefaults.standard.set(index, forKey: indexKey)
    }

    static func remove(macID: String) {
        removePSK(for: macID)
        var index = UserDefaults.standard.dictionary(forKey: indexKey) as? [String: String] ?? [:]
        index.removeValue(forKey: macID)
        UserDefaults.standard.set(index, forKey: indexKey)
    }

    private static func psk(for macID: String) -> Data? {
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

    private static func setPSK(_ psk: Data, for macID: String) {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: macID,
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = psk
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        let status = SecItemAdd(add as CFDictionary, nil)
        if status != errSecSuccess {
            Log.info("pairing: keychain store failed (\(status))")
        }
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

/// One-shot pairing listener: ephemeral port, advertised over Bonjour as
/// the video service type with a `pair=1` TXT flag, under the receiver's
/// connection at a time; a failed PIN proof invalidates the PIN (the UI
/// shows the fresh one) and drops the connection. After
/// `maxFailedAttempts` the listener shuts down entirely.
final class PairingServer {
    private let serviceName: String
    private let onPaired: (_ macID: String, _ macName: String, _ psk: Data) -> Void
    private let onPINChanged: (_ pin: String) -> Void
    private let queue = DispatchQueue(label: "pairing.server")
    private var listener: NWListener?
    private var active: NWConnection?
    private(set) var pin = PairingCrypto.makePIN()
    private var failedAttempts = 0
    private let maxFailedAttempts = 5

    init(serviceName: String,
         onPaired: @escaping (_ macID: String, _ macName: String, _ psk: Data) -> Void,
         onPINChanged: @escaping (_ pin: String) -> Void) {
        self.serviceName = serviceName
        self.onPaired = onPaired
        self.onPINChanged = onPINChanged
    }

    func start() {
        queue.async { self.startListener() }
    }

    func stop() {
        queue.async {
            self.active?.cancel()
            self.active = nil
            self.listener?.cancel()
            self.listener = nil
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
            // One pairing at a time; a newcomer replaces a stalled attempt.
            self.active?.cancel()
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
        var salt = Data(count: 16)
        _ = salt.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
        }
        PairingWire.receive(PairStart.self, on: conn) { [weak self] start in
            guard let self, conn === self.active else { return }
            guard let start, let clientPub = Data(base64Encoded: start.pub),
                  let clientKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: clientPub),
                  let shared = try? serverKey.sharedSecretFromKeyAgreement(with: clientKey)
            else { return self.reject(conn, reason: "protocol error", newPIN: false) }

            let challenge = PairChallenge(
                pub: serverKey.publicKey.rawRepresentation.base64EncodedString(),
                salt: salt.base64EncodedString())
            guard let frame = PairingWire.frame(challenge) else { return }
            conn.send(content: frame, completion: .contentProcessed { _ in })

            PairingWire.receive(PairProof.self, on: conn) { [weak self] proof in
                guard let self, conn === self.active else { return }
                let confirm = PairingCrypto.confirmKey(shared: shared, salt: salt)
                guard let proof, let proofData = Data(base64Encoded: proof.proof),
                      PairingCrypto.validProof(proofData, confirmKey: confirm, pin: self.pin,
                                               clientPub: clientPub,
                                               serverPub: serverKey.publicKey.rawRepresentation)
                else {
                    // Wrong PIN (or tampering): the PIN is spent either way.
                    return self.reject(conn, reason: "wrong PIN", newPIN: true)
                }

                let psk = PairingCrypto.psk(shared: shared, salt: salt)
                let ok = PairResult(type: "pair-ok", deviceID: PhoneReceiverInstallID.value)
                if let frame = PairingWire.frame(ok) {
                    conn.send(content: frame, completion: .contentProcessed { _ in
                        conn.cancel()
                    })
                }
                Log.info("pairing: paired with \"\(start.name)\"")
                self.onPaired(start.installID, start.name, psk)
                // Single-use: this server instance is done.
                self.listener?.cancel()
                self.listener = nil
            }
        }
    }

    private func reject(_ conn: NWConnection, reason: String, newPIN: Bool) {
        Log.info("pairing: rejected (\(reason))")
        if let frame = PairingWire.frame(PairResult(type: "pair-fail",
                                                    reason: "Pairing failed: \(reason)")) {
            conn.send(content: frame, completion: .contentProcessed { _ in conn.cancel() })
        } else {
            conn.cancel()
        }
        active = nil
        guard newPIN else { return }
        failedAttempts += 1
        if failedAttempts >= maxFailedAttempts {
            Log.info("pairing: too many failed attempts — shutting down")
            listener?.cancel()
            listener = nil
            return
        }
        pin = PairingCrypto.makePIN()
        onPINChanged(pin)
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
