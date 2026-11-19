import Foundation
import SQLite3

// MARK: - Harness

/// Host-runnable checks of the guest-independent GuestTrustStore logic: the
/// install/remove/list store logic against a temp sqlite file (the verified
/// 5-column `tsettings` schema) with an injected trustd-restart closure and
/// injected uuid/subject providers — covering per-domain rows, the one-
/// transaction rollback, the REQ-007 restart-, DB- and provider-failure errors,
/// the REQ-006 input rejects, and the SecCertificateCopySubjectSummary subject
/// rendering with its control-char sanitization. `run-trust-store-tests.sh`
/// builds this file with GuestTrustStore.swift (and a stub IcliKit whose
/// kickstartService these checks never reach, since the restart is injected),
/// passing a fixture CA DER as argv[1]. The live-guest trust chain and the
/// TASK-007 live-schema check stay VM-gated.
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

struct StubRestartFailure: Error, CustomStringConvertible { let description = "stub kickstart failed" }

nonisolated(unsafe) var restartCalls: [(label: String, kill: Bool)] = []

func stubRestart(_ label: String, _ kill: Bool) throws { restartCalls.append((label, kill)) }
func failingRestart(_ label: String, _ kill: Bool) throws {
    restartCalls.append((label, kill))
    throw StubRestartFailure()
}

/// A uuid provider that resolves live uuids, except it throws for `failing`.
func uuidProvider(failing: GuestTrustStore.Domain? = nil) -> GuestTrustStore.UUIDProvider {
    { domain in
        if domain == failing {
            throw GuestAPIError.operationFailed("injected \(domain.rawValue)-domain provider failure")
        }
        return try GuestTrustStore.Domain.liveUUID(domain)
    }
}

/// A subject provider that throws (the SecCertificateCopyNormalizedSubjectSequence
/// failure path).
func failingSubject(_ certificate: SecCertificate) throws -> Data {
    throw GuestAPIError.operationFailed("injected subject provider failure")
}

/// A temp TrustStore DB, with the verified 5-column `tsettings` schema unless
/// `schema` is false.
func makeStore(directory: String, schema: Bool = true) -> String {
    let path = directory + "/TrustStore-\(UUID().uuidString).sqlite3"
    var db: OpaquePointer?
    sqlite3_open(path, &db)
    if schema {
        sqlite3_exec(db, "CREATE TABLE tsettings (sha256 BLOB NOT NULL, subj BLOB NOT NULL, "
            + "tset BLOB, data BLOB, uuid BLOB NOT NULL, UNIQUE(sha256,uuid))", nil, nil, nil)
        sqlite3_exec(db, "CREATE INDEX isubj ON tsettings(subj)", nil, nil, nil)
    }
    sqlite3_close(db)
    return path
}

func rowCount(_ path: String) -> Int {
    var db: OpaquePointer?
    var statement: OpaquePointer?
    sqlite3_open(path, &db)
    defer { sqlite3_close(db) }
    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM tsettings", -1, &statement, nil)
    defer { sqlite3_finalize(statement) }
    return sqlite3_step(statement) == SQLITE_ROW ? Int(sqlite3_column_int(statement, 0)) : -1
}

/// Rows for a sha256 hex, as (uuid hex) list.
func uuidHexes(_ path: String, sha256Hex: String) -> [String] {
    var db: OpaquePointer?
    var statement: OpaquePointer?
    sqlite3_open(path, &db)
    defer { sqlite3_close(db) }
    sqlite3_prepare_v2(db, "SELECT uuid FROM tsettings WHERE sha256 = x'\(sha256Hex)' ORDER BY uuid", -1, &statement, nil)
    defer { sqlite3_finalize(statement) }
    var out: [String] = []
    while sqlite3_step(statement) == SQLITE_ROW {
        let data = Data(bytes: sqlite3_column_blob(statement, 0), count: Int(sqlite3_column_bytes(statement, 0)))
        out.append(GuestTrustStore.hexString(data))
    }
    return out
}

/// The (tset is NULL, data, subj) of the row at (sha256, uuid), or nil if absent.
func rowPayload(_ path: String, sha256Hex: String, uuidHex: String) -> (tsetIsNull: Bool, data: Data, subj: Data)? {
    var db: OpaquePointer?
    var statement: OpaquePointer?
    sqlite3_open(path, &db)
    defer { sqlite3_close(db) }
    sqlite3_prepare_v2(db, "SELECT tset, data, subj FROM tsettings WHERE sha256 = x'\(sha256Hex)' AND uuid = x'\(uuidHex)'",
                       -1, &statement, nil)
    defer { sqlite3_finalize(statement) }
    guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
    func column(_ index: Int32) -> Data {
        guard let pointer = sqlite3_column_blob(statement, index) else { return Data() }
        return Data(bytes: pointer, count: Int(sqlite3_column_bytes(statement, index)))
    }
    return (sqlite3_column_type(statement, 0) == SQLITE_NULL, column(1), column(2))
}

func pem(fromDER der: Data) -> String {
    "-----BEGIN CERTIFICATE-----\n" + der.base64EncodedString(options: [.lineLength64Characters])
        + "\n-----END CERTIFICATE-----\n"
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

    /// REQ-006: the daemon counts certificates by `-----BEGIN CERTIFICATE-----`
    /// marker occurrences — more than one is a multi-cert bundle naming the
    /// limit, exactly one passes `validate`. Zero markers passes `validate` and
    /// is rejected as not PEM by the decoder (see `storeLogic`).
    static func certificateCountReject() {
        let block = "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n"
        let two = caughtMessage { try GuestTrustStore.validate(pem: block + block) }
        expect(two?.contains("2 certificates") == true && two?.contains("exactly one") == true,
               "two-cert bundle rejected naming the limit, got \(String(describing: two))")

        let one = caughtMessage { try GuestTrustStore.validate(pem: block) }
        expect(one == nil, "single-cert PEM passes validate, got \(String(describing: one))")
    }

    /// REQ-006: every C0 control char (0x00–0x1F) or DEL (0x7F) becomes a single
    /// space; other characters are untouched; an empty summary stays empty.
    static func subjectSummarySanitization() {
        expectEqual(GuestTrustStore.sanitize(summary: "A\rB\u{1b}C"), "A B C",
                    "CR and ESC each become a space")
        expectEqual(GuestTrustStore.sanitize(summary: "ok\u{00}\u{1f}\u{7f}!"), "ok   !",
                    "NUL, unit-separator and DEL each become a space")
        expectEqual(GuestTrustStore.sanitize(summary: "clean name"), "clean name",
                    "a clean summary is unchanged")
        expectEqual(GuestTrustStore.sanitize(summary: ""), "", "an empty summary stays empty")
        expectEqual(GuestTrustStore.sanitize(summary: "\u{20}~\u{80}é"), "\u{20}~\u{80}é",
                    "0x20, 0x7E and non-ASCII are untouched")
    }

    /// REQ-006/REQ-007: a fixture CA renders its common-name summary; an
    /// undecodable DER (SecCertificateCopySubjectSummary yields nothing) renders
    /// the empty string; the store logic runs against the fixture.
    static func subjectSummaryFromFixture() {
        expectEqual(GuestTrustStore.subjectSummary(fromCertificateDER: Data([0x00, 0x01, 0x02])), "",
                    "a cert with no summary renders empty")
        expectEqual(GuestTrustStore.subjectSummary(fromCertificateDER: Data()), "",
                    "empty DER renders empty")

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
        storeLogic(der: der)
    }

    /// REQ-006/REQ-007: per-domain install/remove/list against a temp DB with an
    /// injected restart and providers; transaction rollback; restart-, DB- and
    /// provider-failure errors; REQ-006 input rejects.
    static func storeLogic(der: Data) {
        let directory = NSTemporaryDirectory() + "trust-store-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let certificatePEM = pem(fromDER: der)
        guard let expected = try? GuestTrustStore.anchor(fromPEM: certificatePEM) else {
            expect(false, "fixture PEM decodes to an anchor")
            return
        }
        let sha256Hex = GuestTrustStore.hexString(expected.sha256)
        let userHex = (try? GuestTrustStore.hexString(GuestTrustStore.liveUserUUID())) ?? ""
        let adminHex = (try? GuestTrustStore.hexString(GuestTrustStore.liveAdminUUID())) ?? ""
        expect(userHex.count == 32 && adminHex.count == 32 && userHex != adminHex,
               "live user and admin uuids are distinct 16-byte values")

        // install (user only): one user-domain row, restart(kill: true), domains ["user"]
        let path = makeStore(directory: directory)
        // junk row at the same (sha256, uuid): INSERT OR REPLACE must overwrite it
        var seed: OpaquePointer?
        sqlite3_open(path, &seed)
        sqlite3_exec(seed, "INSERT INTO tsettings (sha256, subj, tset, data, uuid) "
            + "VALUES (x'\(sha256Hex)', x'0a0b', x'0c', x'0d0e', x'\(userHex)')", nil, nil, nil)
        sqlite3_close(seed)
        restartCalls = []
        let installed = try? GuestTrustStore.install(pem: certificatePEM, admin: false,
                                                     at: path, restart: stubRestart)
        expectEqual(installed?.anchor, expected, "install returns the decoded anchor")
        expectEqual(installed?.domains.map(\.rawValue) ?? [], ["user"], "install(admin:false) domains = [user]")
        expectEqual(rowCount(path), 1, "install wrote one row")
        expectEqual(uuidHexes(path, sha256Hex: sha256Hex), [userHex], "the row's uuid is the user domain")
        expect(restartCalls.count == 1 && restartCalls[0].label == "com.apple.trustd" && restartCalls[0].kill,
               "install restarts com.apple.trustd with kill: true")
        let payload = rowPayload(path, sha256Hex: sha256Hex, uuidHex: userHex)
        expect(payload?.tsetIsNull == true, "user row is a default-trust root (tset NULL)")
        expectEqual(payload?.data, der, "user row data is the full cert DER (junk replaced)")
        expectEqual(payload?.subj, expected.subject, "user row subj is the normalized subject sequence")
        expect(payload?.subj != Data([0x0a, 0x0b]), "junk subj is gone")

        // install (admin): user + admin rows, domains ["admin","user"]
        restartCalls = []
        let both = try? GuestTrustStore.install(pem: certificatePEM, admin: true, at: path, restart: stubRestart)
        expectEqual(both?.domains.map(\.rawValue) ?? [], ["admin", "user"], "install(admin:true) domains = [admin,user]")
        expectEqual(rowCount(path), 2, "install(admin:true) wrote the second (admin) row")
        expectEqual(uuidHexes(path, sha256Hex: sha256Hex).sorted(), [userHex, adminHex].sorted(),
                    "both user and admin rows present")

        // idempotency: a reinstall with admin:false keeps the admin row; domains still [admin,user]
        let reinstalled = try? GuestTrustStore.install(pem: certificatePEM, admin: false, at: path, restart: stubRestart)
        expectEqual(reinstalled?.domains.map(\.rawValue) ?? [], ["admin", "user"],
                    "reinstall(admin:false) reports all domains the anchor is in")
        expectEqual(rowCount(path), 2, "reinstall(admin:false) does not drop the admin row")

        // list: {sha256, subject, domains}
        let anchors = (try? GuestTrustStore.list(at: path)) ?? []
        expectEqual(anchors.map { GuestTrustStore.hexString($0.sha256) }, [sha256Hex], "list sha256")
        expectEqual(anchors.first?.subject, "Test CA", "list subject")
        expectEqual(anchors.first?.domains.map(\.rawValue) ?? [], ["admin", "user"], "list domains aggregated")

        // list: a provider failure (user or admin) throws
        for failing in [GuestTrustStore.Domain.user, .admin] {
            let listFail = caughtMessage { _ = try GuestTrustStore.list(at: path, userUUID: uuidProvider(failing: failing)) }
            expect(listFail?.contains("injected \(failing.rawValue)-domain provider failure") == true,
                   "list throws when the \(failing.rawValue) provider fails: \(String(describing: listFail))")
        }

        // list filters rows whose uuid is not a supported domain
        let filtered = makeStore(directory: directory)
        var db: OpaquePointer?
        sqlite3_open(filtered, &db)
        let strayUUID = String(repeating: "cd", count: 16)
        sqlite3_exec(db, "INSERT INTO tsettings (sha256, subj, tset, data, uuid) "
            + "VALUES (x'\(String(repeating: "ab", count: 32))', x'00', NULL, x'00', x'\(strayUUID)')",
                     nil, nil, nil)
        sqlite3_close(db)
        expectEqual((try? GuestTrustStore.list(at: filtered))?.count, 0,
                    "a row in an unsupported domain is not listed")

        // remove: unknown sha256 -> removed false, no restart; known -> true, all rows gone, restart
        restartCalls = []
        let unknown = try? GuestTrustStore.remove(sha256: Data(repeating: 1, count: 32), at: path, restart: stubRestart)
        expectEqual(unknown?.removed, false, "remove of an unknown sha256 returns removed=false")
        expectEqual(restartCalls.count, 0, "unknown-sha256 remove does not restart trustd")
        let removed = try? GuestTrustStore.remove(sha256: expected.sha256, at: path, restart: stubRestart)
        expectEqual(removed?.removed, true, "remove returns removed=true for a real anchor")
        expectEqual(removed?.domains.map(\.rawValue).sorted() ?? [], ["admin", "user"],
                    "remove reports the domains it removed")
        expectEqual(rowCount(path), 0, "remove deleted every domain's row")
        expect(restartCalls.count == 1 && restartCalls[0].kill, "remove restarts trustd once with kill: true")

        // removeAnchor: error kinds + messages, then success deletes the rows
        func removeAnchorError(_ hex: String, at target: String) -> GuestAPIError? {
            do { _ = try GuestTrustStore.removeAnchor(at: target, sha256Hex: hex, restart: stubRestart) } catch {
                return error as? GuestAPIError
            }
            return nil
        }
        let badHex = "ZZ-not-hex"
        let badError = removeAnchorError(badHex, at: path)
        if case .invalidRequest(let message, _)? = badError {
            expect(message.contains(badHex), "bad-hex message names the value: \(message)")
        } else {
            expect(false, "bad hex throws invalidRequest, got \(String(describing: badError))")
        }
        let upperError = removeAnchorError(sha256Hex.uppercased(), at: path)
        if case .invalidRequest? = upperError {} else {
            expect(false, "uppercase hex throws invalidRequest, got \(String(describing: upperError))")
        }
        let unknownHex = String(repeating: "01", count: 32)
        let unknownError = removeAnchorError(unknownHex, at: path)
        if case .notFound(let message, let hint)? = unknownError {
            expect(message.contains(unknownHex), "notFound message names the sha256: \(message)")
            expect(hint?.contains("ca_list") == true, "notFound hint points to ca_list: \(String(describing: hint))")
        } else {
            expect(false, "unknown sha256 throws notFound, got \(String(describing: unknownError))")
        }
        let anchorPath = makeStore(directory: directory)
        _ = try? GuestTrustStore.install(pem: certificatePEM, admin: true, at: anchorPath, restart: stubRestart)
        restartCalls = []
        let removedAnchor = try? GuestTrustStore.removeAnchor(at: anchorPath, sha256Hex: sha256Hex, restart: stubRestart)
        expectEqual(removedAnchor?.sha256, sha256Hex, "removeAnchor returns the normalized sha256")
        expectEqual(removedAnchor?.domains.map(\.rawValue) ?? [], ["admin", "user"], "removeAnchor returns the domains removed")
        expectEqual(rowCount(anchorPath), 0, "removeAnchor deleted the rows")
        expectEqual(restartCalls.count, 1, "removeAnchor restarts trustd once")

        // transaction rollback: a trigger aborting the admin-uuid insert leaves ZERO rows, no restart
        let rollbackPath = makeStore(directory: directory)
        sqlite3_open(rollbackPath, &db)
        sqlite3_exec(db, "CREATE TRIGGER no_admin BEFORE INSERT ON tsettings WHEN new.uuid = x'\(adminHex)' "
            + "BEGIN SELECT RAISE(ABORT, 'no admin row'); END", nil, nil, nil)
        sqlite3_close(db)
        restartCalls = []
        let aborted = caughtMessage {
            _ = try GuestTrustStore.install(pem: certificatePEM, admin: true, at: rollbackPath, restart: stubRestart)
        }
        expect(aborted != nil, "install(admin:true) with an aborting admin insert returns a DB error")
        expectEqual(rowCount(rollbackPath), 0, "the aborted transaction leaves zero rows (user row rolled back)")
        expectEqual(restartCalls.count, 0, "a rolled-back install never restarts trustd")

        // provider failure: user, admin (incl. admin:false), and subject each abort before any write/restart
        for failing in [GuestTrustStore.Domain.user, .admin] {
            for admin in [true, false] {
                let providerPath = makeStore(directory: directory)
                restartCalls = []
                let message = caughtMessage {
                    _ = try GuestTrustStore.install(pem: certificatePEM, admin: admin, at: providerPath,
                                                    restart: stubRestart, userUUID: uuidProvider(failing: failing))
                }
                expect(message != nil, "install(admin:\(admin)) with the \(failing.rawValue) provider failing errors")
                expectEqual(rowCount(providerPath), 0, "a \(failing.rawValue)-provider failure writes no row")
                expectEqual(restartCalls.count, 0, "a \(failing.rawValue)-provider failure never restarts trustd")
            }
        }
        let subjectPath = makeStore(directory: directory)
        restartCalls = []
        let subjectFail = caughtMessage {
            _ = try GuestTrustStore.install(pem: certificatePEM, admin: false, at: subjectPath,
                                            restart: stubRestart, subject: failingSubject)
        }
        expect(subjectFail != nil, "install with the subject provider failing errors")
        expectEqual(rowCount(subjectPath), 0, "a subject-provider failure writes no row")
        expectEqual(restartCalls.count, 0, "a subject-provider failure never restarts trustd")
        // ca_remove resolves providers before DELETE: a provider failure leaves the rows
        let removeProviderPath = makeStore(directory: directory)
        _ = try? GuestTrustStore.install(pem: certificatePEM, admin: true, at: removeProviderPath, restart: stubRestart)
        restartCalls = []
        let removeFail = caughtMessage {
            _ = try GuestTrustStore.remove(sha256: expected.sha256, at: removeProviderPath,
                                           restart: stubRestart, userUUID: uuidProvider(failing: .admin))
        }
        expect(removeFail != nil, "remove with a provider failing errors")
        expectEqual(rowCount(removeProviderPath), 2, "a provider failure leaves the anchor's rows intact")
        expectEqual(restartCalls.count, 0, "a provider failure on remove never restarts trustd")

        // restart failure: rows kept (no rollback); error names trustd, row outcome, recovery
        let installPath = makeStore(directory: directory)
        let installFailure = caughtMessage {
            _ = try GuestTrustStore.install(pem: certificatePEM, admin: false, at: installPath, restart: failingRestart)
        }
        expect(installFailure?.contains("trustd") == true && installFailure?.contains("were written") == true
            && installFailure?.contains("not reloaded") == true && installFailure?.contains("Retry the install") == true
            && installFailure?.contains("stub kickstart failed") == true && installFailure?.contains(installPath) == true,
            "install restart failure names trustd, row written, recovery: \(String(describing: installFailure))")
        expectEqual(rowCount(installPath), 1, "install restart failure leaves the row (no rollback)")
        _ = try? GuestTrustStore.install(pem: certificatePEM, admin: false, at: installPath, restart: stubRestart)
        expectEqual(rowCount(installPath), 1, "retry after restart is fixed leaves exactly one row")

        let removeFailure = caughtMessage {
            _ = try GuestTrustStore.remove(sha256: expected.sha256, at: installPath, restart: failingRestart)
        }
        expect(removeFailure?.contains("trustd") == true && removeFailure?.contains("WERE removed") == true
            && removeFailure?.contains("not reloaded") == true && removeFailure?.contains("Do not retry") == true
            && removeFailure?.contains("kickstartService") == true && removeFailure?.contains(installPath) == true,
            "remove restart failure names trustd, row removed, restart-not-retry: \(String(describing: removeFailure))")
        expectEqual(rowCount(installPath), 0, "remove restart failure leaves the row deleted (no rollback)")

        // DB access failures: error names the DB path; no restart
        let noTablePath = makeStore(directory: directory, schema: false)
        restartCalls = []
        for (label, target) in [("absent file", directory + "/absent.sqlite3"), ("missing table", noTablePath)] {
            let results: [(String, String?)] = [
                ("install", caughtMessage {
                    _ = try GuestTrustStore.install(pem: certificatePEM, admin: false, at: target, restart: stubRestart)
                }),
                ("remove", caughtMessage {
                    _ = try GuestTrustStore.remove(sha256: expected.sha256, at: target, restart: stubRestart)
                }),
                ("list", caughtMessage { _ = try GuestTrustStore.list(at: target) }),
            ]
            for (method, message) in results {
                expect(message?.contains(target) == true,
                       "\(method) on \(label) names the DB path: \(String(describing: message))")
            }
        }
        expectEqual(restartCalls.count, 0, "DB failures never restart trustd")

        // REQ-006 rejects: right cause, nothing written, no restart
        let rejectPath = makeStore(directory: directory)
        func rejected(_ input: String) -> String? {
            caughtMessage { try GuestTrustStore.install(pem: input, admin: false, at: rejectPath, restart: stubRestart) }
        }
        func padded(_ bytes: Int) -> String {
            "-----BEGIN CERTIFICATE-----\n" + String(repeating: "A", count: bytes) + "\n-----END CERTIFICATE-----\n"
        }
        let framing = padded(0).utf8.count
        expect(rejected(padded(GuestTrustStore.maxPEMBytes - framing + 1))?.contains("64 KiB") == true,
               "PEM one byte over 64 KiB rejected naming the limit")
        expect(rejected(padded(GuestTrustStore.maxPEMBytes - framing))?.contains("64 KiB") != true,
               "PEM of exactly 64 KiB is not rejected for size")
        expect(rejected("-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n")?
            .contains("not valid base64") == true, "bad-base64 body rejected")
        expect(rejected("-----BEGIN CERTIFICATE-----\nAAECAw==\n-----END CERTIFICATE-----\n")?
            .contains("not a valid DER") == true, "non-DER body rejected")
        expect(rejected("nothing here\n")?.contains("not PEM-encoded") == true, "zero-marker input rejected as not PEM")
        expect(rejected("-----BEGIN CERTIFICATE----------BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n")?
            .contains("2 certificates") == true, "markers are counted by occurrence, not by line")
        expectEqual(rowCount(rejectPath), 0, "rejected input writes no row")
        expectEqual(restartCalls.count, 0, "rejected input does not restart trustd")

        // remove sha256 hex parse (the daemon rejects nil as invalid_param, changing no rows)
        expect(GuestTrustStore.sha256(fromHex: "zz" + String(repeating: "0", count: 62)) == nil, "non-hex sha256 rejected")
        expect(GuestTrustStore.sha256(fromHex: String(repeating: "a", count: 63)) == nil, "short sha256 rejected")
        expect(GuestTrustStore.sha256(fromHex: String(repeating: "a", count: 65)) == nil, "over-length sha256 rejected")
        expectEqual(GuestTrustStore.sha256(fromHex: String(repeating: "Ab", count: 32)), Data(repeating: 0xAB, count: 32),
                    "valid 64-hex sha256 parses case-insensitively")
    }
}
