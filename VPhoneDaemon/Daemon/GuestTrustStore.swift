import CryptoKit
import Darwin
import Foundation
import IcliKit
import Security
import SQLite3

/// `int mbr_uid_to_uuid(uid_t id, uuid_t uu)` from `<membership.h>` (libSystem),
/// which the Darwin module does not surface. Fills `uu` (16 bytes) with the
/// uuid the membership subsystem maps the uid to; returns 0 on success.
@_silgen_name("mbr_uid_to_uuid")
private func mbr_uid_to_uuid(_ id: uid_t, _ uu: UnsafeMutablePointer<UInt8>) -> Int32

/// `int gethostuuid(uuid_t id, const struct timespec *wait)` from libSystem.
/// The SDK marks it unavailable for iOS, so the daemon's Mac Catalyst build
/// cannot call Darwin's declaration, though libSystem exports it at runtime on
/// macOS/Catalyst. Bind the symbol directly, as `mbr_uid_to_uuid` above does.
@_silgen_name("gethostuuid")
private func vp_gethostuuid(_ uu: UnsafeMutablePointer<UInt8>, _ wait: UnsafePointer<timespec>) -> Int32

/// Reads and writes the guest TrustStore — the sqlite DB trustd consults for
/// user-installed anchors at
/// `/private/var/protected/trustd/private/TrustStore.sqlite3`.
///
/// The verified `tsettings` schema is
/// `tsettings(sha256 BLOB NOT NULL, subj BLOB NOT NULL, tset BLOB, data BLOB, uuid BLOB NOT NULL, UNIQUE(sha256,uuid))`
/// with `INDEX isubj ON tsettings(subj)`. An anchor row is written as a
/// fully-trusted root (`tset` = NULL) so an intercepting proxy's certificates
/// validate for every policy. trustd evaluates anchors by `subj` AND `uuid`
/// (`SELECT data FROM tsettings WHERE subj=? AND uuid=?`), deriving the
/// evaluation `uuid` from the calling process, so a row is honored only in its
/// own trust domain. Two domains are supported: the **user** domain
/// (`uuid = mbr_uid_to_uuid(501)`, mobile apps) and the **admin** domain
/// (`uuid = gethostuuid()`, all uids incl. system daemons).
///
/// trustd keeps the store cached in memory, so every change is followed by an
/// in-process `kickstartService("com.apple.trustd", kill: true)`; `kill: false`
/// would leave the stale cache in place.
enum GuestTrustStore {
    static let storePath = "/private/var/protected/trustd/private/TrustStore.sqlite3"
    static let trustdLabel = "com.apple.trustd"
    /// Bounded wait for a locked store; stays under the 30 s client RPC timeout.
    static let busyTimeoutMilliseconds: Int32 = 5000
    /// A CA PEM must be one certificate no larger than 64 KiB.
    static let maxPEMBytes = 64 * 1024

    /// A trust domain: which caller `uuid` honors the anchor. `admin` sorts
    /// before `user` (the REQ-006 `domains` ordering is bytewise on the name).
    enum Domain: String, CaseIterable {
        case admin
        case user

        /// The 16-byte domain `uuid`, resolved live from the system providers.
        static func liveUUID(_ domain: Domain) throws -> Data {
            switch domain {
            case .user: return try liveUserUUID()
            case .admin: return try liveAdminUUID()
            }
        }
    }

    /// Resolves a domain's 16-byte `uuid`. Injectable so tests can force a
    /// provider failure. A thrown error aborts the operation before any row
    /// changes (REQ-007 provider-failure).
    typealias UUIDProvider = (_ domain: Domain) throws -> Data
    /// Resolves a certificate's normalized subject sequence (`subj`). Injectable
    /// so tests can force the `SecCertificateCopyNormalizedSubjectSequence`
    /// failure path.
    typealias SubjectProvider = (_ certificate: SecCertificate) throws -> Data

    /// user domain `uuid = mbr_uid_to_uuid(501)` (raw 16 bytes).
    static func liveUserUUID() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        let rc = mbr_uid_to_uuid(501, &bytes)
        guard rc == 0 else {
            throw GuestAPIError.operationFailed(
                "Resolving the user trust domain failed: mbr_uid_to_uuid(501) returned \(rc).")
        }
        return Data(bytes)
    }

    /// admin domain `uuid = gethostuuid()` (raw 16 bytes). The `wait` timespec
    /// must be non-NULL; a zero wait returns the host uuid immediately.
    static func liveAdminUUID() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        var wait = timespec(tv_sec: 0, tv_nsec: 0)
        let rc = vp_gethostuuid(&bytes, &wait)
        guard rc == 0 else {
            throw GuestAPIError.operationFailed(
                "Resolving the admin trust domain failed: gethostuuid() returned \(rc) (errno \(errno)).")
        }
        return Data(bytes)
    }

    static func liveSubject(_ certificate: SecCertificate) throws -> Data {
        guard let subject = SecCertificateCopyNormalizedSubjectSequence(certificate) as Data? else {
            throw GuestAPIError.invalidRequest(
                "The CA certificate has no readable subject.",
                hint: "Pass a CA certificate with a subject name.")
        }
        return subject
    }

    /// How the store restarts trustd. Injectable so tests can assert the call
    /// without touching launchd. Production restarts trustd in-process; a
    /// thrown error becomes the install/remove failure (no row rollback).
    typealias TrustdRestart = (_ label: String, _ kill: Bool) throws -> Void
    static func liveRestart(_ label: String, _ kill: Bool) throws {
        _ = try kickstartService(label, kill: kill)
    }

    /// A decoded anchor ready to write: full DER plus its derived TrustStore keys.
    struct Anchor: Equatable {
        /// Full certificate DER — the `data` column.
        let der: Data
        /// DER of the certificate's normalized subject — the `subj` column.
        let subject: Data
        /// SHA-256 of the full certificate DER — the `sha256` key (32 bytes).
        let sha256: Data
    }

    // MARK: - Decoding

    /// Decode a PEM certificate into its full DER and the derived `subj`/`sha256`
    /// TrustStore keys. Throws `invalidRequest` when the PEM is not a single
    /// parseable X.509 certificate; rethrows a `subject` provider failure.
    static func anchor(fromPEM pem: String,
                       subject subjectProvider: SubjectProvider = liveSubject) throws -> Anchor {
        let der = try derFromPEM(pem)
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            throw GuestAPIError.invalidRequest(
                "The CA is not a valid DER X.509 certificate.",
                hint: "Pass one PEM-encoded CA certificate.")
        }
        let subject = try subjectProvider(certificate)
        let sha256 = Data(SHA256.hash(data: der))
        return Anchor(der: der, subject: subject, sha256: sha256)
    }

    /// Extract the single base64 DER body between the first PEM CERTIFICATE
    /// markers. Rejects input with no markers or a non-base64 body.
    static func derFromPEM(_ pem: String) throws -> Data {
        let begin = "-----BEGIN CERTIFICATE-----"
        let end = "-----END CERTIFICATE-----"
        guard let beginRange = pem.range(of: begin),
              let endRange = pem.range(of: end, range: beginRange.upperBound ..< pem.endIndex)
        else {
            throw GuestAPIError.invalidRequest(
                "The CA is not PEM-encoded.",
                hint: "Pass a certificate wrapped in -----BEGIN CERTIFICATE----- / -----END CERTIFICATE-----.")
        }
        let base64 = pem[beginRange.upperBound ..< endRange.lowerBound].filter { !$0.isWhitespace }
        guard let der = Data(base64Encoded: base64), !der.isEmpty else {
            throw GuestAPIError.invalidRequest(
                "The CA PEM body is not valid base64.",
                hint: "Re-export the CA in PEM format.")
        }
        return der
    }

    // MARK: - Store operations

    /// Install an anchor: upsert one row per selected trust domain (user always,
    /// admin additionally when `admin` is true) inside ONE `BEGIN IMMEDIATE`
    /// transaction, then restart trustd. All selected-domain uuids and the
    /// subject are resolved BEFORE any write, so a provider failure changes no
    /// row and never restarts trustd. A per-domain INSERT failure rolls the
    /// whole transaction back (zero rows for the sha256) and never restarts. A
    /// restart failure after a committed write surfaces as the operation error
    /// with the rows left in place (no rollback), so a retry after the restart
    /// is fixed replaces the same rows and leaves exactly one per selected
    /// domain. Returns the anchor and every domain the anchor is installed in
    /// after the call (REQ-007 idempotency: pre-existing rows for unselected
    /// domains are kept and reported).
    @discardableResult
    static func install(pem: String,
                        admin: Bool,
                        at path: String = storePath,
                        restart: TrustdRestart = liveRestart,
                        userUUID: UUIDProvider = Domain.liveUUID,
                        subject: SubjectProvider = liveSubject) throws -> (anchor: Anchor, domains: [Domain]) {
        try validate(pem: pem)
        let anchor = try anchor(fromPEM: pem, subject: subject)
        // Resolve BOTH domain uuids up front, before any write — a provider
        // failure (incl. the admin provider on an admin:false install, needed
        // to report `domains`) must change no row and never restart trustd.
        let uuidToDomain = try domainUUIDMap(userUUID)
        let selected: [Domain] = admin ? [.user, .admin] : [.user]
        let rows = try selected.map { (domain: $0, uuid: try resolveUUID($0, userUUID)) }
        let db = try open(path)
        defer { sqlite3_close(db) }
        try transaction(db) {
            for row in rows {
                try run(db,
                        "INSERT OR REPLACE INTO tsettings (sha256, subj, tset, data, uuid) VALUES (?, ?, NULL, ?, ?)",
                        blobs: [anchor.sha256, anchor.subject, anchor.der, row.uuid])
            }
        }
        do { try restart(trustdLabel, true) } catch {
            throw GuestAPIError.operationFailed(
                "The anchor row(s) were written to \(path) but trustd (\(trustdLabel)) could not be restarted "
                    + "(\(error)); the live trust store was not reloaded. "
                    + "Retry the install (it is idempotent), restart trustd, or reboot the guest.")
        }
        return (anchor, try domains(forSHA256: anchor.sha256, uuidToDomain: uuidToDomain, db: db))
    }

    /// Remove every row whose `sha256` matches (all domains). Both domain uuids
    /// are resolved BEFORE the DELETE (to report the domains removed and so a
    /// provider failure leaves the rows intact). Restart trustd and return
    /// `removed: true` with the domains the anchor had only when a row was
    /// deleted; a non-matching `sha256` changes nothing, skips the restart, and
    /// returns `removed: false`. A restart failure after a real delete surfaces
    /// as the error (the rows are already gone — recover by restarting trustd,
    /// not retrying).
    @discardableResult
    static func remove(sha256: Data,
                       at path: String = storePath,
                       restart: TrustdRestart = liveRestart,
                       userUUID: UUIDProvider = Domain.liveUUID) throws -> (removed: Bool, domains: [Domain]) {
        // Resolve BOTH providers first: a failure must leave the rows untouched.
        let uuidToDomain = try domainUUIDMap(userUUID)
        let db = try open(path)
        defer { sqlite3_close(db) }
        let present = try domains(forSHA256: sha256, uuidToDomain: uuidToDomain, db: db)
        try run(db, "DELETE FROM tsettings WHERE sha256 = ?", blobs: [sha256])
        guard sqlite3_changes(db) > 0 else { return (false, []) }
        do { try restart(trustdLabel, true) } catch {
            throw GuestAPIError.operationFailed(
                "The anchor row(s) WERE removed from \(path) but trustd (\(trustdLabel)) could not be restarted "
                    + "(\(error)); the live trust store was not reloaded. "
                    + "Do not retry the remove: restart trustd "
                    + "(kickstartService(\"\(trustdLabel)\", kill: true)) or reboot the guest.")
        }
        return (true, present)
    }

    /// Remove an anchor by its 64-char lowercase-hex sha256; returns that
    /// normalized hex and the domains removed. A malformed value throws
    /// `invalidRequest`; a sha256 with no installed row throws `notFound`.
    static func removeAnchor(at path: String = storePath,
                             sha256Hex hex: String,
                             restart: TrustdRestart = liveRestart,
                             userUUID: UUIDProvider = Domain.liveUUID) throws -> (sha256: String, domains: [Domain]) {
        guard hex == hex.lowercased(), let sha256 = sha256(fromHex: hex) else {
            throw GuestAPIError.invalidRequest(
                "sha256 must be 64 lowercase hex characters; got '\(hex)'.",
                hint: "Pass the sha256 shown by security.ca_list.")
        }
        let removed = try remove(sha256: sha256, at: path, restart: restart, userUUID: userUUID)
        guard removed.removed else {
            throw GuestAPIError.notFound(
                "No installed CA has sha256 \(hex).",
                hint: "Run security.ca_list to see installed CAs.")
        }
        return (hexString(sha256), removed.domains)
    }

    /// List every user-installed anchor — rows whose `uuid` is a supported
    /// domain — as its lowercase-hex `sha256` key, subject summary (from
    /// `SecCertificateCopySubjectSummary` on the stored certificate), and the
    /// domains it is installed in. One entry per distinct `sha256`, its
    /// `domains` aggregating its rows. Both domain uuids are resolved first.
    static func list(at path: String = storePath,
                     userUUID: UUIDProvider = Domain.liveUUID)
        throws -> [(sha256: Data, subject: String, domains: [Domain])] {
        // Resolve BOTH providers first: a failure must surface before any read.
        let uuidToDomain = try domainUUIDMap(userUUID)
        let db = try open(path)
        defer { sqlite3_close(db) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT sha256, data, uuid FROM tsettings", -1, &statement, nil) == SQLITE_OK
        else { throw storeError(db) }
        defer { sqlite3_finalize(statement) }
        // Preserve first-seen DER per sha256; accumulate domains.
        var order: [Data] = []
        var ders: [Data: Data] = [:]
        var domainsBySHA: [Data: Set<Domain>] = [:]
        while sqlite3_step(statement) == SQLITE_ROW {
            let sha256 = blob(statement, 0)
            let der = blob(statement, 1)
            let uuid = blob(statement, 2)
            guard let domain = uuidToDomain[uuid] else { continue }
            if ders[sha256] == nil { ders[sha256] = der; order.append(sha256) }
            domainsBySHA[sha256, default: []].insert(domain)
        }
        return order.map { sha in
            (sha, subjectSummary(fromCertificateDER: ders[sha] ?? Data()), sorted(domainsBySHA[sha] ?? []))
        }
    }

    /// The domains an anchor currently occupies, from the live rows for `sha256`.
    private static func domains(forSHA256 sha256: Data,
                                uuidToDomain: [Data: Domain],
                                db: OpaquePointer) throws -> [Domain] {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT uuid FROM tsettings WHERE sha256 = ?", -1, &statement, nil) == SQLITE_OK
        else { throw storeError(db) }
        defer { sqlite3_finalize(statement) }
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        _ = sha256.withUnsafeBytes { raw in
            sqlite3_bind_blob(statement, 1, raw.baseAddress, Int32(sha256.count), transient)
        }
        var found: Set<Domain> = []
        while sqlite3_step(statement) == SQLITE_ROW {
            if let domain = uuidToDomain[blob(statement, 0)] { found.insert(domain) }
        }
        return sorted(found)
    }

    /// Resolve both domain uuids once and map uuid bytes → domain. Resolving
    /// both is required on every CA call because computing an anchor's `domains`
    /// needs both; a provider failure throws here before any row changes.
    private static func domainUUIDMap(_ userUUID: UUIDProvider) throws -> [Data: Domain] {
        var map: [Data: Domain] = [:]
        for domain in Domain.allCases { map[try resolveUUID(domain, userUUID)] = domain }
        return map
    }

    /// One domain's `uuid`; an empty blob is a provider failure, never written or matched.
    private static func resolveUUID(_ domain: Domain, _ provider: UUIDProvider) throws -> Data {
        let uuid = try provider(domain)
        guard !uuid.isEmpty else {
            throw GuestAPIError.operationFailed(
                "Resolving the \(domain.rawValue) trust domain returned an empty uuid.")
        }
        return uuid
    }

    private static func sorted(_ domains: Set<Domain>) -> [Domain] {
        domains.sorted { $0.rawValue < $1.rawValue }
    }

    // MARK: - SQLite

    private static func open(_ path: String) throws -> OpaquePointer {
        var handle: OpaquePointer?
        let rc = sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE, nil)
        guard rc == SQLITE_OK, let db = handle else {
            let message = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "cannot open database"
            sqlite3_close(handle)
            throw GuestAPIError.operationFailed(
                "The guest TrustStore \(path) could not be opened: \(message).",
                hint: "Confirm the CFW guest exposes \(storePath).")
        }
        sqlite3_busy_timeout(db, busyTimeoutMilliseconds)
        return db
    }

    /// Run `body` inside a `BEGIN IMMEDIATE` … `COMMIT` transaction; any thrown
    /// error triggers a `ROLLBACK` (leaving zero rows) and is rethrown.
    private static func transaction(_ db: OpaquePointer, _ body: () throws -> Void) throws {
        try exec(db, "BEGIN IMMEDIATE")
        do {
            try body()
            try exec(db, "COMMIT")
        } catch {
            _ = try? exec(db, "ROLLBACK")
            throw error
        }
    }

    private static func exec(_ db: OpaquePointer, _ sql: String) throws {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw storeError(db) }
    }

    private static func run(_ db: OpaquePointer, _ sql: String, blobs: [Data]) throws {
        // sqlite must copy each bound blob — the backing Data is transient.
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else { throw storeError(db) }
        defer { sqlite3_finalize(statement) }
        for (offset, blob) in blobs.enumerated() {
            let index = Int32(offset + 1)
            let rc = blob.withUnsafeBytes { raw in
                sqlite3_bind_blob(statement, index, raw.baseAddress, Int32(blob.count), transient)
            }
            guard rc == SQLITE_OK else { throw storeError(db) }
        }
        guard sqlite3_step(statement) == SQLITE_DONE else { throw storeError(db) }
    }

    private static func blob(_ statement: OpaquePointer?, _ column: Int32) -> Data {
        guard let pointer = sqlite3_column_blob(statement, column) else { return Data() }
        return Data(bytes: pointer, count: Int(sqlite3_column_bytes(statement, column)))
    }

    private static func storeError(_ db: OpaquePointer) -> GuestAPIError {
        let path = sqlite3_db_filename(db, "main").map { String(cString: $0) } ?? storePath
        return GuestAPIError.operationFailed(
            "The guest TrustStore \(path) operation failed: \(String(cString: sqlite3_errmsg(db))).")
    }

    // MARK: - Input validation

    /// Reject a PEM over 64 KiB, or with more than one `-----BEGIN CERTIFICATE-----`
    /// marker (a multi-cert bundle). Zero markers is left to `derFromPEM`'s
    /// not-PEM reject. Mirrors the host CLI's count so the daemon enforces the
    /// rule independently of how the PEM arrived.
    static func validate(pem: String) throws {
        let bytes = pem.utf8.count
        guard bytes <= maxPEMBytes else {
            throw GuestAPIError.invalidRequest(
                "The CA PEM is \(bytes) bytes, over the 64 KiB (\(maxPEMBytes)-byte) limit.",
                hint: "Install a single certificate under 64 KiB.")
        }
        let certificates = pem.components(separatedBy: "-----BEGIN CERTIFICATE-----").count - 1
        guard certificates <= 1 else {
            throw GuestAPIError.invalidRequest(
                "The CA PEM holds \(certificates) certificates; install exactly one.",
                hint: "Split the bundle and install the root CA alone.")
        }
    }

    /// Parse a 64-character hex SHA-256 into its 32 bytes; nil when the input is
    /// not exactly 64 hex digits.
    static func sha256(fromHex hex: String) -> Data? {
        guard hex.count == 64, hex.allSatisfy(\.isHexDigit) else { return nil }
        var data = Data(capacity: 32)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index ..< next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data
    }

    /// Lowercase hex of a byte blob (the `sha256` presentation form).
    static func hexString(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Subject summary

    /// The certificate's subject summary (typically its common name) from
    /// `SecCertificateCopySubjectSummary` on the stored DER, sanitized by
    /// `sanitize(summary:)`. A certificate with no summary renders as the
    /// empty string.
    static func subjectSummary(fromCertificateDER der: Data) -> String {
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData),
              let summary = SecCertificateCopySubjectSummary(certificate) as String?
        else { return "" }
        return sanitize(summary: summary)
    }

    /// Replace every C0 control character (0x00–0x1F) or DEL (0x7F) in a subject
    /// summary with a single space so the one-line `ca list` format stays
    /// unambiguous; the rest of the summary is left intact.
    static func sanitize(summary: String) -> String {
        var sanitized = ""
        for scalar in summary.unicodeScalars {
            if scalar.value <= 0x1F || scalar.value == 0x7F {
                sanitized.append(" ")
            } else {
                sanitized.unicodeScalars.append(scalar)
            }
        }
        return sanitized
    }
}
