#!/bin/zsh
set -euo pipefail

# Builds the guest-independent GuestTrustStore logic with TrustStoreTests.swift
# for the Mac and runs them: install/remove/list against a temp sqlite file with
# an injected restart closure (restart- and DB-failure errors), the REQ-006
# input rejects, and the SecCertificateCopySubjectSummary subject rendering with
# its control-char sanitization. GuestTrustStore imports IcliKit only for
# kickstartService, which the injected restart never reaches, so a one-line
# stub module stands in. A fixture CA (CN=Test CA) is generated with openssl and
# passed as argv[1]. No guest is needed.

daemon="${0:a:h:h}"
temporary="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/vphone-trust-store-tests.XXXXXX")"
trap '/bin/rm -rf "$temporary"' EXIT

compiler=("${SWIFTC:-swiftc}")
[[ -x /usr/bin/xcrun ]] && compiler=(/usr/bin/xcrun --sdk macosx swiftc)
extension=so
[[ $(uname -s) == Darwin ]] && extension=dylib

print -r -- 'import Foundation
public func kickstartService(_ label: String, kill: Bool) throws -> [String: Any] { [:] }' \
    > "$temporary/IcliKit.swift"

flags=(-swift-version 6 -module-cache-path "$temporary/modules" -I "$temporary" -L "$temporary")

"${compiler[@]}" "${flags[@]}" -emit-library -emit-module -module-name IcliKit \
    "$temporary/IcliKit.swift" -o "$temporary/libIcliKit.$extension"

"${compiler[@]}" "${flags[@]}" -parse-as-library -lIcliKit -Xlinker -rpath -Xlinker "$temporary" \
    "$daemon/Daemon/GuestMethodSpec.swift" \
    "$daemon/Daemon/GuestPaging.swift" \
    "$daemon/Daemon/GuestTrustStore.swift" \
    "$daemon/Tests/TrustStoreTests.swift" \
    -o "$temporary/trust-store-tests"

/usr/bin/openssl req -x509 -newkey rsa:2048 -keyout "$temporary/key.pem" -nodes -days 1 \
    -subj "/CN=Test CA" -outform DER -out "$temporary/cert.der" 2>/dev/null

"$temporary/trust-store-tests" "$temporary/cert.der"
