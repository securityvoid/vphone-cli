import Foundation
import Security
import CryptoKit

// MARK: - Harness

/// Host-runnable checks of the guest-independent GuestTrustStore logic: the
/// admin-domain install/remove/list flow driven through injected
/// `GuestTrustStore.SPI` fakes (no live trustd), covering the all-or-none
/// install flow and its rollback, the SPI-failure / malformed-CopyAll /
/// SPI-unavailable / NULL-store paths, the serial-queue serialization, the
/// REQ-006 input rejects, and the `SecCertificateCopySubjectSummary` subject
/// rendering with its control-char sanitization. `run-trust-store-tests.sh`
/// builds this file with GuestTrustStore.swift and passes a fixture CA DER as
/// argv[1]. The live-guest uid-501 trust chain stays VM-gated (TASK-007).
nonisolated(unsafe) var failures = 0
nonisolated(unsafe) var checks = 0

func expect(_ condition: Bool, _ message: @autoclosure () -> String, line: Int = #line) {
    checks += 1
    if !condition {
        failures += 1
        print("FAIL line \(line): \(message())")
    }
}

func expectEqual<T: Equatable>(_ actual: T, _ expected: T, _ message: String = "", line: Int = #line) {
    expect(actual == expected, "\(message) expected \(expected), got \(actual)", line: line)
}

/// Run `body` and return the thrown GuestAPIError's message, or nil if it did
/// not throw a GuestAPIError.
func caughtMessage(_ body: () throws -> Void) -> String? {
    do {
        try body()
        return nil
    } catch let error as GuestAPIError {
        return error.description
    } catch {
        return nil
    }
}

/// Run `body` and return the thrown GuestAPIError's wire code, or nil if it did
/// not throw a GuestAPIError.
func caughtCode(_ body: () throws -> Void) -> String? {
    do {
        try body()
        return nil
    } catch let error as GuestAPIError {
        return error.code
    } catch {
        return nil
    }
}

// MARK: - SPI fake

/// A programmable, call-recording fake of `GuestTrustStore.SPI`. `store` holds
/// the DERs currently "installed"; the closures record each call in `calls` and
/// honor the configured statuses / apply flags so a test can reproduce every
/// REQ-007 failure branch without a live trustd.
final class FakeSPI: @unchecked Sendable {
    var store: [Data]
    var calls: [String] = []

    var forDomainReturnsNull = false
    let handle = OpaquePointer(bitPattern: 0x1)!

    var setStatus: OSStatus = errSecSuccess
    var setApplies = true

    var removeStatus: OSStatus = errSecSuccess
    var removeApplies = true

    var copyAllStatus: OSStatus = errSecSuccess
    var copyAllCount = 0
    /// Override for precise per-invocation CopyAll behavior (index is 0-based).
    var copyAllOverride: ((_ index: Int, _ store: [Data]) -> (OSStatus, CFArray?))?

    /// Serialization hooks (case g): the first `set` invocation blocks on
    /// `setGate` after signalling `setEntered`; later invocations do not block.
    var setInvocations = 0
    let setEntered = DispatchSemaphore(value: 0)
    let setGate = DispatchSemaphore(value: 0)
    var blockFirstSet = false
    var failSecondSet = false

    init(store: [Data] = []) { self.store = store }

    static func der(of cert: SecCertificate) -> Data { SecCertificateCopyData(cert) as Data }

    static func contents(from store: [Data]) -> CFArray {
        (store.map { [$0, NSNull()] as [Any] }) as CFArray
    }

    /// A CopyAll array with one element that is a 1-item array (malformed).
    static func malformedOneItem() -> CFArray { [[Data([0x30, 0x00])] as [Any]] as CFArray }

    /// A CopyAll array whose single element carries an undecodable DER.
    static func malformedBadDER() -> CFArray { [[Data([0x00, 0x01, 0x02]), NSNull()] as [Any]] as CFArray }

    func spi() -> GuestTrustStore.SPI {
        GuestTrustStore.SPI(
            forDomain: { _ in
                self.calls.append("forDomain")
                return self.forDomainReturnsNull ? nil : self.handle
            },
            set: { _, cert in
                self.calls.append("set")
                let n = self.setInvocations
                self.setInvocations += 1
                if self.blockFirstSet && n == 0 {
                    self.setEntered.signal()
                    self.setGate.wait()
                }
                if self.setApplies { self.store.append(FakeSPI.der(of: cert)) }
                if self.failSecondSet && n == 1 { return errSecIO }
                return self.setStatus
            },
            remove: { _, cert in
                self.calls.append("remove")
                if self.removeApplies {
                    let der = FakeSPI.der(of: cert)
                    self.store.removeAll { $0 == der }
                }
                return self.removeStatus
            },
            copyAll: { _ in
                self.calls.append("copyAll")
                let index = self.copyAllCount
                self.copyAllCount += 1
                if let override = self.copyAllOverride { return override(index, self.store) }
                return (self.copyAllStatus, FakeSPI.contents(from: self.store))
            })
    }
}

func pem(fromDER der: Data) -> String {
    let body = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
    return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n"
}

/// A resolveSPI that throws the SPI-unavailable error (case d).
func unavailableSPI() throws -> GuestTrustStore.SPI {
    throw GuestAPIError.operationFailed(
        "The trust-store SPI SecTrustStoreCopyAll could not be resolved via dlsym; this guest build does not export it.")
}

@main
enum TrustStoreTests {
    static func main() {
        certificateCountReject()
        subjectSummarySanitization()
        subjectSummaryFromFixture()
        print("trust-store: \(checks) checks, \(failures) failures")
        exit(failures == 0 ? 0 : 1)
    }

    // MARK: REQ-006 input validation (unchanged logic)

    static func certificateCountReject() {
        let block = "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n"
        let two = caughtMessage { try GuestTrustStore.validate(pem: block + block) }
        expect(two?.contains("2 certificates") == true && two?.contains("exactly one") == true,
               "two-cert bundle rejected naming the limit, got \(String(describing: two))")

        let one = caughtMessage { try GuestTrustStore.validate(pem: block) }
        expect(one == nil, "single-cert PEM passes validate, got \(String(describing: one))")

        expect(GuestTrustStore.sha256(fromHex: "zz" + String(repeating: "0", count: 62)) == nil, "non-hex sha256 rejected")
        expect(GuestTrustStore.sha256(fromHex: String(repeating: "a", count: 63)) == nil, "short sha256 rejected")
        expect(GuestTrustStore.sha256(fromHex: String(repeating: "a", count: 65)) == nil, "over-length sha256 rejected")
        expectEqual(GuestTrustStore.sha256(fromHex: String(repeating: "Ab", count: 32)), Data(repeating: 0xAB, count: 32),
                    "valid 64-hex sha256 parses case-insensitively")
    }

    static func subjectSummarySanitization() {
        expectEqual(GuestTrustStore.sanitize(summary: "A\rB\u{1b}C"), "A B C", "CR and ESC each become a space")
        expectEqual(GuestTrustStore.sanitize(summary: "ok\u{00}\u{1f}\u{7f}!"), "ok   !",
                    "NUL, unit-separator and DEL each become a space")
        expectEqual(GuestTrustStore.sanitize(summary: "clean name"), "clean name", "a clean summary is unchanged")
        expectEqual(GuestTrustStore.sanitize(summary: ""), "", "an empty summary stays empty")
        expectEqual(GuestTrustStore.sanitize(summary: "\u{20}~\u{80}é"), "\u{20}~\u{80}é",
                    "0x20, 0x7E and non-ASCII are untouched")
    }

    static func subjectSummaryFromFixture() {
        expectEqual(GuestTrustStore.subjectSummary(fromCertificateDER: Data([0x00, 0x01, 0x02])), "",
                    "a cert with no summary renders empty")
        expectEqual(GuestTrustStore.subjectSummary(fromCertificateDER: Data()), "", "empty DER renders empty")

        guard CommandLine.arguments.count > 1 else {
            print("FAIL: fixture CA DER path not supplied as argv[1]")
            failures += 1
            return
        }
        let path = CommandLine.arguments[1]
        guard let der = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            print("FAIL: cannot read fixture CA DER at \(path)")
            failures += 1
            return
        }
        expectEqual(GuestTrustStore.subjectSummary(fromCertificateDER: der), "Test CA",
                    "fixture CA renders its common-name summary")
        let sha256 = Data(SHA256Shim.hash(der))
        spiFlow(der: der, sha256: sha256)
        caDispatchFlow(der: der, sha256: sha256)
    }

    // MARK: RPC dispatch (REQ-006) — GuestSecurityCADispatch param keys + reply shape

    /// The `security.ca_*` dispatch arms as `executeDevice` calls them: the RPC
    /// param keys (`pem`/`sha256`) and the exact reply fields, driven through the
    /// same SPI fakes. Proves the dispatch wires install/remove/list to the right
    /// GuestTrustStore call and emits only the declared keys (no `domains`).
    static func caDispatchFlow(der: Data, sha256: Data) {
        let certPEM = pem(fromDER: der)
        let hex = GuestTrustStore.hexString(sha256)

        // install {pem} ⇒ {sha256, subject}, and nothing else.
        do {
            let fake = FakeSPI()
            let reply = try? GuestSecurityCADispatch.install(["pem": certPEM], resolveSPI: fake.spi)
            expectEqual(reply?["sha256"] as? String, hex, "ca_install reply sha256 is the DER digest hex")
            expectEqual(reply?["subject"] as? String, "Test CA", "ca_install reply subject is the summary")
            expectEqual(reply?.keys.sorted(), ["sha256", "subject"], "ca_install reply has only sha256,subject (no domains)")
            expect(fake.store.contains(der), "ca_install wires through to the trust-store install")
        }

        // install with a missing or empty pem ⇒ invalidRequest naming pem, no SPI call.
        // MUTATION: change the install arm's key from "pem" ⇒ this rejects a valid call.
        for bad in [[:] as [String: Any], ["pem": ""], ["pem": 7]] {
            let fake = FakeSPI()
            let message = caughtMessage { _ = try GuestSecurityCADispatch.install(bad, resolveSPI: fake.spi) }
            expect(message?.contains("pem is required") == true,
                   "ca_install rejects missing/empty pem naming pem, got \(String(describing: message))")
            expect(fake.calls.isEmpty, "ca_install makes no SPI call on a bad pem, calls=\(fake.calls)")
        }

        // remove {sha256} ⇒ {removed: true, sha256}, wiring to the trust-store remove.
        do {
            let fake = FakeSPI(store: [der])
            let reply = try? GuestSecurityCADispatch.remove(["sha256": hex], resolveSPI: fake.spi)
            expectEqual(reply?["removed"] as? Bool, true, "ca_remove reply removed is true")
            expectEqual(reply?["sha256"] as? String, hex, "ca_remove reply echoes the normalized hex")
            expectEqual(reply?.keys.sorted(), ["removed", "sha256"], "ca_remove reply has only removed,sha256")
            expect(fake.store.isEmpty, "ca_remove wires through to the trust-store remove")
        }

        // remove with a missing, empty or non-string sha256 ⇒ invalidRequest naming
        // sha256, no SPI call.
        for bad in [[:] as [String: Any], ["sha256": ""], ["sha256": 5]] {
            let fake = FakeSPI()
            let message = caughtMessage { _ = try GuestSecurityCADispatch.remove(bad, resolveSPI: fake.spi) }
            expect(message?.contains("sha256 is required") == true,
                   "ca_remove rejects \(bad) naming sha256, got \(String(describing: message))")
            expect(fake.calls.isEmpty, "ca_remove makes no SPI call on a bad sha256 \(bad), calls=\(fake.calls)")
        }

        // list ⇒ {anchors: [{sha256, subject}]}, each entry only those keys.
        do {
            let fake = FakeSPI(store: [der])
            let reply = try? GuestSecurityCADispatch.list(resolveSPI: fake.spi)
            expectEqual(reply?.keys.sorted(), ["anchors"], "ca_list reply has only anchors")
            let anchors = reply?["anchors"] as? [[String: Any]]
            expectEqual(anchors?.count, 1, "ca_list returns one anchor for one installed cert")
            expectEqual(anchors?.first?["sha256"] as? String, hex, "ca_list anchor sha256 is the digest hex")
            expectEqual(anchors?.first?["subject"] as? String, "Test CA", "ca_list anchor subject is the summary")
            expectEqual(anchors?.first?.keys.sorted(), ["sha256", "subject"], "ca_list anchor has only sha256,subject (no domains)")
        }
    }

    // MARK: Admin-domain SPI flow (REQ-007)

    static func spiFlow(der: Data, sha256: Data) {
        let certPEM = pem(fromDER: der)
        let hex = GuestTrustStore.hexString(sha256)
        let otherHex = GuestTrustStore.hexString(Data(repeating: 0xAB, count: 32))

        // Happy path: install adds the cert, list shows it, remove clears it.
        do {
            let fake = FakeSPI()
            let anchor = try? GuestTrustStore.install(pem: certPEM, resolveSPI: fake.spi)
            expect(anchor?.sha256 == sha256, "install returns the anchor with the DER's sha256")
            expect(fake.calls.contains("set"), "install calls SecTrustStoreSetTrustSettings")
            let listed = try? GuestTrustStore.list(resolveSPI: fake.spi)
            expect(listed?.count == 1 && listed?.first?.sha256 == sha256, "list shows the installed anchor")
            expect(listed?.first?.subject == "Test CA", "list renders the subject summary")
            let removedHex = try? GuestTrustStore.removeAnchor(sha256Hex: hex, resolveSPI: fake.spi)
            expectEqual(removedHex, hex, "remove returns the normalized hex")
            expect(fake.store.isEmpty, "remove clears the admin store")
        }

        // Idempotency: re-installing a pre-present cert is success.
        do {
            let fake = FakeSPI(store: [der])
            let anchor = try? GuestTrustStore.install(pem: certPEM, resolveSPI: fake.spi)
            expect(anchor?.sha256 == sha256, "idempotent re-install of a pre-present cert succeeds")
        }

        // (a) post-write verify failure: set returns success but CopyAll omits
        // the cert ⇒ install errors naming both SPIs, rolls back, leaves nothing.
        // MUTATION (a): delete the cert-absent finishFailure branch in install
        // (the final `try finishFailure(... "did not take effect" ...)`) ⇒ install
        // would return the anchor and this check fails.
        do {
            let fake = FakeSPI()
            fake.setApplies = false
            let message = caughtMessage { _ = try GuestTrustStore.install(pem: certPEM, resolveSPI: fake.spi) }
            expect(message?.contains("SecTrustStoreSetTrustSettings") == true
                && message?.contains("SecTrustStoreCopyAll") == true
                && message?.contains("not present in the admin trust store after the write") == true,
                "(a) cert-absent install names both SPIs and the not-present cause, got \(String(describing: message))")
            expect(fake.calls.contains("remove"), "(a) a not-pre-present failed install rolls back with remove")
            expect(fake.store.isEmpty, "(a) rollback leaves nothing installed")
        }

        // (b0) write failed but cert landed, not pre-present ⇒ remove is called
        // and removes it.
        do {
            let fake = FakeSPI()
            fake.setStatus = errSecIO
            fake.setApplies = true
            let message = caughtMessage { _ = try GuestTrustStore.install(pem: certPEM, resolveSPI: fake.spi) }
            expect(message?.contains("SecTrustStoreSetTrustSettings failed") == true,
                   "(b0) write-failed install names SecTrustStoreSetTrustSettings, got \(String(describing: message))")
            expect(fake.calls.contains("remove"), "(b0) a landed-but-failed write is rolled back")
            expect(fake.store.isEmpty, "(b0) rollback removes the landed cert")
        }

        // (b0) pre-present cert with a failed re-install is left intact (no remove).
        do {
            let fake = FakeSPI(store: [der])
            fake.setStatus = errSecIO
            let message = caughtMessage { _ = try GuestTrustStore.install(pem: certPEM, resolveSPI: fake.spi) }
            expect(message?.contains("SecTrustStoreSetTrustSettings failed") == true,
                   "(b0) failed re-install surfaces the SPI error")
            expect(!fake.calls.contains("remove"), "(b0) a pre-present cert is never rolled back")
            expect(fake.store.contains(der), "(b0) the pre-present cert stays installed")
        }

        // (b) SPI failures each surface the SPI error and never report success.
        do {
            let listFail = FakeSPI()
            listFail.copyAllStatus = errSecIO
            let listMessage = caughtMessage { _ = try GuestTrustStore.list(resolveSPI: listFail.spi) }
            expect(listMessage?.contains("SecTrustStoreCopyAll failed") == true,
                   "(b) list surfaces a CopyAll failure, got \(String(describing: listMessage))")

            let removeFail = FakeSPI(store: [der])
            removeFail.removeStatus = errSecIO
            removeFail.removeApplies = false   // a failing remove does not mutate the store
            let removeMessage = caughtMessage { _ = try GuestTrustStore.removeAnchor(sha256Hex: hex, resolveSPI: removeFail.spi) }
            expect(removeMessage?.contains("SecTrustStoreRemoveCertificate failed") == true,
                   "(b) remove surfaces a RemoveCertificate failure, got \(String(describing: removeMessage))")
            expect(removeFail.store.contains(der), "(b) a failed remove leaves the cert installed")
        }

        // (b1) NULL store ⇒ install errors naming SecTrustStoreForDomain and
        // calls none of set/remove/copyAll.
        // MUTATION (b1): delete the `guard let store = spi.forDomain(...) else`
        // NULL-store guard (force-unwrap) ⇒ set/copyAll would be called and this
        // check fails.
        do {
            let fake = FakeSPI()
            fake.forDomainReturnsNull = true
            let message = caughtMessage { _ = try GuestTrustStore.install(pem: certPEM, resolveSPI: fake.spi) }
            expect(message?.contains("SecTrustStoreForDomain returned NULL") == true,
                   "(b1) NULL store names SecTrustStoreForDomain, got \(String(describing: message))")
            expect(!fake.calls.contains("set") && !fake.calls.contains("remove") && !fake.calls.contains("copyAll"),
                   "(b1) NULL store makes no set/remove/copyAll call, calls=\(fake.calls)")
        }

        // (c) malformed CopyAll at the PRE-write enumeration ⇒ install errors
        // naming CopyAll and never calls set.
        for (label, contents) in [("one-item", FakeSPI.malformedOneItem()), ("bad-DER", FakeSPI.malformedBadDER())] {
            let fake = FakeSPI()
            fake.copyAllOverride = { _, _ in (errSecSuccess, contents) }
            let message = caughtMessage { _ = try GuestTrustStore.install(pem: certPEM, resolveSPI: fake.spi) }
            expect(message?.contains("SecTrustStoreCopyAll") == true,
                   "(c) pre-write \(label) names CopyAll, got \(String(describing: message))")
            expect(!fake.calls.contains("set"), "(c) pre-write-bad \(label) never calls set, calls=\(fake.calls)")
        }
        do {
            let fake = FakeSPI()
            fake.copyAllOverride = { index, _ in (index == 0 ? errSecIO : errSecSuccess, nil) }
            let message = caughtMessage { _ = try GuestTrustStore.install(pem: certPEM, resolveSPI: fake.spi) }
            expect(message?.contains("SecTrustStoreCopyAll failed") == true,
                   "(c) pre-write non-zero CopyAll names CopyAll, got \(String(describing: message))")
            expect(!fake.calls.contains("set"), "(c) pre-write non-zero CopyAll never calls set")
        }
        // (c) malformed CopyAll at the POST-write enumeration ⇒ rollback + error.
        do {
            let fake = FakeSPI()
            fake.copyAllOverride = { index, store in
                index == 1 ? (errSecSuccess, FakeSPI.malformedOneItem()) : (errSecSuccess, FakeSPI.contents(from: store))
            }
            let message = caughtMessage { _ = try GuestTrustStore.install(pem: certPEM, resolveSPI: fake.spi) }
            expect(message?.contains("SecTrustStoreCopyAll") == true,
                   "(c) post-write malformed CopyAll names CopyAll, got \(String(describing: message))")
            expect(fake.calls.contains("set") && fake.calls.contains("remove"),
                   "(c) post-write malformed CopyAll rolls back after the write")
        }
        // (c) malformed CopyAll through list and remove.
        do {
            let listFake = FakeSPI()
            listFake.copyAllOverride = { _, _ in (errSecSuccess, FakeSPI.malformedBadDER()) }
            expect(caughtMessage { _ = try GuestTrustStore.list(resolveSPI: listFake.spi) }?.contains("SecTrustStoreCopyAll") == true,
                   "(c) list surfaces a malformed CopyAll naming CopyAll")

            let removeFake = FakeSPI()
            removeFake.copyAllOverride = { _, _ in (errSecSuccess, FakeSPI.malformedOneItem()) }
            expect(caughtMessage { _ = try GuestTrustStore.removeAnchor(sha256Hex: hex, resolveSPI: removeFake.spi) }?
                .contains("SecTrustStoreCopyAll") == true,
                   "(c) remove surfaces a malformed CopyAll naming CopyAll")
            expect(!removeFake.calls.contains("remove"), "(c) a malformed find never calls RemoveCertificate")
        }

        // (d) dlsym-unavailable ⇒ every method rethrows the SPI-unavailable error.
        do {
            for (method, message) in [
                ("install", caughtMessage { _ = try GuestTrustStore.install(pem: certPEM, resolveSPI: unavailableSPI) }),
                ("remove", caughtMessage { _ = try GuestTrustStore.removeAnchor(sha256Hex: hex, resolveSPI: unavailableSPI) }),
                ("list", caughtMessage { _ = try GuestTrustStore.list(resolveSPI: unavailableSPI) }),
            ] {
                expect(message?.contains("could not be resolved via dlsym") == true,
                       "(d) \(method) surfaces the SPI-unavailable error, got \(String(describing: message))")
            }
            // remove of an absent sha256 ⇒ notFound, no RemoveCertificate call.
            let empty = FakeSPI()
            let message = caughtMessage { _ = try GuestTrustStore.removeAnchor(sha256Hex: otherHex, resolveSPI: empty.spi) }
            expect(message?.contains("No installed CA has sha256") == true,
                   "(d) remove of an absent sha256 is notFound, got \(String(describing: message))")
            expect(!empty.calls.contains("remove"), "(d) an absent-sha256 remove calls no RemoveCertificate")
            expect(message?.contains("sha256 \(otherHex) in") == true,
                   "(d) not-found names the exact requested sha256, got \(String(describing: message))")
            do {
                try GuestTrustStore.removeAnchor(sha256Hex: otherHex, resolveSPI: FakeSPI().spi)
                expect(false, "(d) absent-sha256 remove should throw")
            } catch let error as GuestAPIError {
                if case let .notFound(_, hint) = error {
                    expect(hint?.contains("ca_list") == true, "(d) not-found hint names ca_list, got \(String(describing: hint))")
                } else {
                    expect(false, "(d) absent-sha256 remove is notFound, got \(error)")
                }
            } catch {
                expect(false, "(d) unexpected error \(error)")
            }
        }

        // (e) undo failure ⇒ error names both SPIs + both OSStatus, "may still be
        // installed", "ca list"; not success.
        // MUTATION (e): delete the `if removeStatus != errSecSuccess { throw ... }`
        // undo-failure branch in finishFailure ⇒ the original error surfaces
        // instead and this check fails.
        do {
            let fake = FakeSPI()
            fake.setApplies = false          // post-write absent
            fake.removeStatus = errSecIO     // rollback remove fails
            let message = caughtMessage { _ = try GuestTrustStore.install(pem: certPEM, resolveSPI: fake.spi) }
            expect(message?.contains("SecTrustStoreSetTrustSettings") == true
                && message?.contains("SecTrustStoreRemoveCertificate") == true
                && message?.contains("may still be installed") == true
                && message?.contains("security.ca_list") == true,
                "(e) undo failure names both SPIs and the recovery path, got \(String(describing: message))")
        }

        // (f) remove reports success but the re-check still shows the cert ⇒ error,
        // never {removed:true}.
        // MUTATION (f): delete the post-remove re-check `if ... contains ... throw`
        // in removeAnchor ⇒ removeAnchor would return the hex and this check fails.
        do {
            let fake = FakeSPI(store: [der])
            fake.removeApplies = false       // remove returns 0 but does not remove
            let message = caughtMessage { _ = try GuestTrustStore.removeAnchor(sha256Hex: hex, resolveSPI: fake.spi) }
            expect(message?.contains("removal did not take effect") == true,
                   "(f) an ineffective remove errors, got \(String(describing: message))")
        }

        // (g) serialization: the first install blocks inside set while holding the
        // serial queue; a second install cannot run its pre-check CopyAll until
        // the first returns; both complete and the cert remains listed.
        // MUTATION (g): remove the `try queue.sync { ... }` wrapper in install ⇒
        // the second pre-check runs during the block and copyAllCount != 1.
        do {
            let fake = FakeSPI()
            fake.blockFirstSet = true
            fake.failSecondSet = true
            let group = DispatchGroup()
            group.enter()
            DispatchQueue.global().async {
                _ = try? GuestTrustStore.install(pem: certPEM, resolveSPI: fake.spi)
                group.leave()
            }
            fake.setEntered.wait()                           // first install is blocked in set
            let copyAllWhileBlocked = fake.copyAllCount      // exactly the first pre-check
            group.enter()
            DispatchQueue.global().async {
                _ = try? GuestTrustStore.install(pem: certPEM, resolveSPI: fake.spi)
                group.leave()
            }
            Thread.sleep(forTimeInterval: 0.2)
            expectEqual(fake.copyAllCount, copyAllWhileBlocked,
                        "(g) the second install's pre-check does not run while the first holds the serial queue")
            expectEqual(copyAllWhileBlocked, 1, "(g) only the first install's pre-check ran before the block")
            fake.setGate.signal()                            // release the first install
            group.wait()
            let listed = try? GuestTrustStore.list(resolveSPI: fake.spi)
            expect(listed?.contains { $0.sha256 == sha256 } == true, "(g) the cert is listed after both installs finish")
        }

        installRejects(der: der, certPEM: certPEM)
        removeRejects()
        spiFailureCoverage(der: der, certPEM: certPEM, hex: hex)
    }

    // MARK: install reject coverage (REQ-006)

    static func installRejects(der: Data, certPEM: String) {
        let limit = GuestTrustStore.maxPEMBytes
        let begin = "-----BEGIN CERTIFICATE-----"
        let end = "-----END CERTIFICATE-----"
        func padded(to bytes: Int) -> String { certPEM + String(repeating: " ", count: bytes - certPEM.utf8.count) }

        // Size limit, both sides of the boundary.
        do {
            let fake = FakeSPI()
            let message = caughtMessage { _ = try GuestTrustStore.install(pem: padded(to: limit + 1), resolveSPI: fake.spi) }
            expect(message?.contains("64 KiB") == true, "PEM of 64 KiB + 1 rejected naming the limit, got \(String(describing: message))")
            expect(fake.calls.isEmpty, "oversize PEM makes no SPI call, calls=\(fake.calls)")

            let ok = FakeSPI()
            let anchor = try? GuestTrustStore.install(pem: padded(to: limit), resolveSPI: ok.spi)
            expect(anchor != nil && ok.store.contains(der), "a valid PEM of exactly 64 KiB is accepted")
        }

        let rejects: [(label: String, pem: String, needle: String)] = [
            ("bad base64", begin + "\n!!!not base64!!!\n" + end + "\n", "not valid base64"),
            ("non-DER base64", begin + "\nAAECAw==\n" + end + "\n", "not a valid DER X.509"),
            ("no BEGIN marker", "just some text, not PEM", "not PEM-encoded"),
            ("multi-cert bundle", certPEM + certPEM, "exactly one"),
        ]
        for reject in rejects {
            let fake = FakeSPI()
            let message = caughtMessage { _ = try GuestTrustStore.install(pem: reject.pem, resolveSPI: fake.spi) }
            expect(message?.contains(reject.needle) == true,
                   "\(reject.label) rejected with '\(reject.needle)', got \(String(describing: message))")
            expect(fake.calls.isEmpty, "\(reject.label) makes no SPI call, calls=\(fake.calls)")
            expect(fake.store.isEmpty, "\(reject.label) installs nothing")
        }
    }

    // MARK: remove reject coverage (REQ-006)

    static func removeRejects() {
        let cases: [(label: String, value: String)] = [
            ("non-hex", "ZZ" + String(repeating: "0", count: 62)),
            ("uppercase hex", String(repeating: "A", count: 64)),
            ("63 chars", String(repeating: "a", count: 63)),
            ("65 chars", String(repeating: "a", count: 65)),
        ]
        for c in cases {
            let fake = FakeSPI()
            let code = caughtCode { _ = try GuestTrustStore.removeAnchor(sha256Hex: c.value, resolveSPI: fake.spi) }
            let message = caughtMessage { _ = try GuestTrustStore.removeAnchor(sha256Hex: c.value, resolveSPI: fake.spi) }
            expectEqual(code, "invalid_param", "\(c.label) remove is invalidRequest")
            expect(message?.contains(c.value) == true, "\(c.label) remove names the value, got \(String(describing: message))")
            expect(fake.calls.isEmpty, "\(c.label) remove makes no SPI call, calls=\(fake.calls)")
        }
    }

    // MARK: SPI-failure coverage (REQ-007)

    static func spiFailureCoverage(der: Data, certPEM: String, hex: String) {
        // NULL admin store for remove and list: the NULL error, no copyAll/remove.
        do {
            let removeFake = FakeSPI(store: [der])
            removeFake.forDomainReturnsNull = true
            let removeMessage = caughtMessage { _ = try GuestTrustStore.removeAnchor(sha256Hex: hex, resolveSPI: removeFake.spi) }
            expect(removeMessage?.contains("SecTrustStoreForDomain returned NULL") == true,
                   "NULL store remove names SecTrustStoreForDomain, got \(String(describing: removeMessage))")
            expect(!removeFake.calls.contains("copyAll") && !removeFake.calls.contains("remove"),
                   "NULL store remove makes no copyAll/remove call, calls=\(removeFake.calls)")

            let listFake = FakeSPI(store: [der])
            listFake.forDomainReturnsNull = true
            let listMessage = caughtMessage { _ = try GuestTrustStore.list(resolveSPI: listFake.spi) }
            expect(listMessage?.contains("SecTrustStoreForDomain returned NULL") == true,
                   "NULL store list names SecTrustStoreForDomain, got \(String(describing: listMessage))")
            expect(!listFake.calls.contains("copyAll") && !listFake.calls.contains("remove"),
                   "NULL store list makes no copyAll/remove call, calls=\(listFake.calls)")
        }

        // Non-zero post-write CopyAll ⇒ rollback runs and the CopyAll failure is returned.
        do {
            let fake = FakeSPI()
            fake.copyAllOverride = { index, store in
                index == 1 ? (errSecIO, nil) : (errSecSuccess, FakeSPI.contents(from: store))
            }
            let message = caughtMessage { _ = try GuestTrustStore.install(pem: certPEM, resolveSPI: fake.spi) }
            expect(message?.contains("SecTrustStoreCopyAll failed") == true,
                   "post-write non-zero CopyAll surfaces the original CopyAll failure, got \(String(describing: message))")
            expect(fake.calls.contains("set") && fake.calls.contains("remove"),
                   "post-write non-zero CopyAll rolls back, calls=\(fake.calls)")
            expect(fake.store.isEmpty, "post-write non-zero CopyAll leaves nothing installed")
        }
    }
}

/// The fixture DER's sha256, matching the digest GuestTrustStore itself computes
/// from a parsed certificate; used to build the expected hex keys.
enum SHA256Shim {
    static func hash(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }
}
