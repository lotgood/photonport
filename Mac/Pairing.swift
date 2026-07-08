// SPDX-License-Identifier: GPL-3.0-only
// Part of PhotonPort, a GPL-3.0 fork of OpenDisplay
// (https://github.com/peetzweg/opendisplay, (c) peetzweg and contributors).
// This file (c) 2026 hyupji, added in the fork.

// Pairing (Mac side) — establishes a long-term per-device secret so WiFi
// sessions can run over TLS-PSK instead of plaintext TCP.
//
// Model (simplified Bluetooth numeric-entry pairing):
//   1. The receiver shows a single-use 6-digit PIN and advertises a
//      short-lived pairing instance (the video service type carrying a
//      `pair=1` TXT flag) while its pairing screen is open. No standing
//      unauthenticated surface otherwise.
//   2. The Mac connects and both sides run X25519 ECDH. The Mac proves it
//      knows the PIN with an HMAC over both public keys keyed by a
//      PIN-bound derivation of the shared secret.
//   3. Both sides derive a 32-byte PSK from the ECDH secret (never from
//      the PIN) and store it. Subsequent WiFi connections use TLS-PSK.
//
// Threat notes: a passive observer can offline-crack the 6-digit PIN from
// the proof, but the PIN is single-use and dead by then, and the PSK
// depends on the ECDH secret the observer doesn't have. An active MITM
// must guess the PIN online — one failed proof invalidates it. The wire
// protocol is framed JSON, same [4-byte BE length][payload] as the rest
// of the app.

import Foundation
import Network
import CryptoKit

// MARK: - Wire messages

struct PairStart: Codable {
    var type = "pair-start"
    let name: String        // Mac's user-visible name, shown on the device
    let installID: String   // Mac's stable identity = TLS-PSK identity hint
    let pub: String         // X25519 public key, base64
}

struct PairChallenge: Codable {
    var type = "pair-challenge"
    let pub: String         // receiver's X25519 public key, base64
    let salt: String        // HKDF salt, base64
}

struct PairProof: Codable {
    var type = "pair-proof"
    let proof: String       // HMAC(confirmKey, pin || clientPub || serverPub), base64
}

struct PairResult: Codable {
    var type: String        // "pair-ok" | "pair-fail"
    var deviceID: String?   // receiver's install id (on ok)
    var reason: String?     // human-readable (on fail)
}

// MARK: - Crypto core (identical on both platforms)

enum PairingCrypto {
    // See iOS/Pairing.swift: pairing reuses the authorized video service
    // type with a `pair=1` TXT flag rather than a dedicated type (which
    // would need its own Local Network authorization).
    static let serviceType = "_photonport._tcp"
    static let pairTXTKey = "pair"

    /// confirmKey authenticates the PIN proof; psk is the long-term secret.
    /// Separate HKDF infos keep them cryptographically independent.
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

    /// Binds the PIN AND both public keys, so a MITM substituting keys
    /// cannot replay a proof it observed.
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

    static func psk(for deviceID: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: deviceID,
            kSecReturnData as String: true,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else {
            return nil
        }
        return result as? Data
    }

    static func setPSK(_ psk: Data, for deviceID: String) {
        // Non-migrating, device-only: a long-term network auth key must not
        // sync to other devices or iCloud Keychain.
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: deviceID,
            kSecAttrSynchronizable as String: false,
        ]
        // Update-in-place when present so a failed add can't lose an existing
        // PSK; only add (with the accessibility policy) when absent.
        let attrs: [String: Any] = [
            kSecValueData as String: psk,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(base as CFDictionary, attrs as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var add = base
            add.merge(attrs) { _, new in new }
            let addStatus = SecItemAdd(add as CFDictionary, nil)
            if addStatus != errSecSuccess {
                Log.info("pairing: keychain add failed (\(addStatus))")
            }
        } else if updateStatus != errSecSuccess {
            Log.info("pairing: keychain update failed (\(updateStatus))")
        }
    }

    static func removePSK(for deviceID: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: deviceID,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - Client (drives one pairing exchange)

enum PairingError: LocalizedError {
    case serviceNotFound     // receiver's pairing screen isn't open
    case permissionDenied    // Mac lacks Local Network permission (NoAuth)
    case protocolError
    case rejected(String)    // wrong PIN, receiver said no

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
    static func pair(targetID: String, pin: String, macName: String,
                     macInstallID: String) async throws -> (deviceID: String, psk: Data) {
        let endpoint = try await discover(targetID: targetID)
        return try await exchange(endpoint: endpoint, pin: pin,
                                  macName: macName, macInstallID: macInstallID)
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
            func finish(_ result: Result<NWEndpoint, Error>) -> Bool {
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

    static func exchange(endpoint: NWEndpoint, pin: String, macName: String,
                         macInstallID: String) async throws -> (deviceID: String, psk: Data) {
        let key = Curve25519.KeyAgreement.PrivateKey()
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
                    let start = PairStart(name: macName, installID: macInstallID,
                                          pub: key.publicKey.rawRepresentation.base64EncodedString())
                    guard let frame = PairingWire.frame(start) else { return fail(.protocolError) }
                    conn.send(content: frame, completion: .contentProcessed { _ in })
                    PairingWire.receive(PairChallenge.self, on: conn) { challenge in
                        guard let challenge,
                              let serverPub = Data(base64Encoded: challenge.pub),
                              let salt = Data(base64Encoded: challenge.salt),
                              let serverKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPub),
                              let shared = try? key.sharedSecretFromKeyAgreement(with: serverKey)
                        else { return fail(.protocolError) }

                        let confirm = PairingCrypto.confirmKey(shared: shared, salt: salt)
                        let proof = PairingCrypto.proof(
                            confirmKey: confirm, pin: pin,
                            clientPub: key.publicKey.rawRepresentation, serverPub: serverPub)
                        guard let proofFrame = PairingWire.frame(PairProof(proof: proof.base64EncodedString()))
                        else { return fail(.protocolError) }
                        conn.send(content: proofFrame, completion: .contentProcessed { _ in })

                        PairingWire.receive(PairResult.self, on: conn) { result in
                            guard let result else { return fail(.protocolError) }
                            guard result.type == "pair-ok", let deviceID = result.deviceID else {
                                return fail(.rejected(result.reason ?? "Pairing rejected — check the PIN."))
                            }
                            let psk = PairingCrypto.psk(shared: shared, salt: salt)
                            if done.claim() { cont.resume(returning: (deviceID, psk)) }
                        }
                    }
                case .failed, .cancelled:
                    fail(.protocolError)
                default:
                    break
                }
            }
            conn.start(queue: .global())
            // A malicious/half-open service can accept the TCP connection and
            // never send the next frame; without a deadline pair() suspends
            // forever. Bounded, resume-once via the gate.
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
