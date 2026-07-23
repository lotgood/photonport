import Security
import XCTest
@testable import PhotonPort

final class S04CredentialTests: XCTestCase {
    private final class InMemoryKeychain {
        var value: Data?
        var forcedUpdateStatus: OSStatus?
        var forcedAddStatus: OSStatus?
        var forcedDeleteStatus: OSStatus?
        private(set) var deleteCalls = 0

        func operations() -> PairingKeychainOperations {
            PairingKeychainOperations(
                copyMatching: { [weak self] _ in
                    guard let value = self?.value else { return (errSecItemNotFound, nil) }
                    return (errSecSuccess, value)
                },
                update: { [weak self] _, attributes in
                    guard let self else { return errSecAuthFailed }
                    if let status = self.forcedUpdateStatus { return status }
                    guard self.value != nil else { return errSecItemNotFound }
                    self.value = attributes[kSecValueData as String] as? Data
                    return errSecSuccess
                },
                add: { [weak self] attributes in
                    guard let self else { return errSecAuthFailed }
                    if let status = self.forcedAddStatus { return status }
                    guard self.value == nil else { return errSecDuplicateItem }
                    self.value = attributes[kSecValueData as String] as? Data
                    return errSecSuccess
                },
                delete: { [weak self] _ in
                    guard let self else { return errSecAuthFailed }
                    self.deleteCalls += 1
                    if let status = self.forcedDeleteStatus { return status }
                    guard self.value != nil else { return errSecItemNotFound }
                    self.value = nil
                    return errSecSuccess
                })
        }
    }

    override func tearDown() {
        PairingStore.keychainOperations = .live
        super.tearDown()
    }

    func testSuccessfulReplacementUpdatesExistingCredentialInPlace() {
        let keychain = InMemoryKeychain()
        let old = Data(repeating: 0x11, count: 32)
        let replacement = Data(repeating: 0x22, count: 32)
        keychain.value = old
        PairingStore.keychainOperations = keychain.operations()

        XCTAssertTrue(PairingStore.setPSK(replacement, for: "device"))
        XCTAssertEqual(keychain.value, replacement)
        XCTAssertEqual(keychain.deleteCalls, 0)
    }

    func testFirstCredentialIsAddedNormally() {
        let keychain = InMemoryKeychain()
        let key = Data(repeating: 0x33, count: 32)
        PairingStore.keychainOperations = keychain.operations()

        XCTAssertTrue(PairingStore.setPSK(key, for: "device"))
        XCTAssertEqual(keychain.value, key)
    }

    func testUpdateFailureRetainsExistingCredentialWithoutDeleteAttempt() {
        let keychain = InMemoryKeychain()
        let old = Data(repeating: 0x44, count: 32)
        keychain.value = old
        keychain.forcedUpdateStatus = errSecAuthFailed
        keychain.forcedDeleteStatus = errSecAuthFailed
        PairingStore.keychainOperations = keychain.operations()

        XCTAssertFalse(PairingStore.setPSK(Data(repeating: 0x55, count: 32), for: "device"))
        XCTAssertEqual(keychain.value, old)
        XCTAssertEqual(keychain.deleteCalls, 0)
    }

    func testAddFailureRetainsExistingCredentialWhenUpdateReportsMissing() {
        let keychain = InMemoryKeychain()
        let old = Data(repeating: 0x66, count: 32)
        keychain.value = old
        keychain.forcedUpdateStatus = errSecItemNotFound
        keychain.forcedAddStatus = errSecDuplicateItem
        keychain.forcedDeleteStatus = errSecAuthFailed
        PairingStore.keychainOperations = keychain.operations()

        XCTAssertFalse(PairingStore.setPSK(Data(repeating: 0x77, count: 32), for: "device"))
        XCTAssertEqual(keychain.value, old)
        XCTAssertEqual(keychain.deleteCalls, 0)
    }
    func testDeleteFailureReturnsFalseAndRetainsCredential() {
        let keychain = InMemoryKeychain()
        let old = Data(repeating: 0x88, count: 32)
        keychain.value = old
        keychain.forcedDeleteStatus = errSecAuthFailed
        PairingStore.keychainOperations = keychain.operations()

        XCTAssertFalse(PairingStore.removePSK(for: "device"))
        XCTAssertEqual(keychain.value, old)
        XCTAssertEqual(keychain.deleteCalls, 1)
    }

    func testDeletingMissingCredentialIsIdempotentSuccess() {
        let keychain = InMemoryKeychain()
        PairingStore.keychainOperations = keychain.operations()

        XCTAssertTrue(PairingStore.removePSK(for: "device"))
        XCTAssertNil(keychain.value)
        XCTAssertEqual(keychain.deleteCalls, 1)
    }
}
