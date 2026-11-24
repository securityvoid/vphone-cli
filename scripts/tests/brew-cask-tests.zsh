#!/bin/zsh
# Tests for scripts/brew-cask.zsh against fixture assets served locally.
set -euo pipefail
tests=${0:a:h}
root=${tests:h:h}
script="$root/scripts/brew-cask.zsh"
fx="$tests/fixtures/brew-cask"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/brew-cask-tests.XXXXXX")
server_pid=""
cleanup() {
  [[ -z $server_pid ]] || kill "$server_pid" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT
fail() { print -u2 -r -- "FAIL: $1"; exit 1; }

# Fixture server: python3 http.server over the assets (200/404) plus one
# asset that answers 503.
cat > "$tmp/server.py" <<'PY'
import http.server, sys
root, portfile = sys.argv[1], sys.argv[2]
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=root, **k)
    def _blocked(self):
        if self.path.endswith("vphone-launchpad-1.0.3-notarized.zip"):
            self.send_error(503)
            return True
        return False
    def do_GET(self):
        if not self._blocked():
            super().do_GET()
    def do_HEAD(self):
        if not self._blocked():
            super().do_HEAD()
    def log_message(self, *a):
        pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
open(portfile, "w").write(str(srv.server_address[1]))
srv.serve_forever()
PY
python3 -I "$tmp/server.py" "$fx/assets" "$tmp/port" &
server_pid=$!
for _ in {1..50}; do [[ -s $tmp/port ]] && break; sleep 0.1; done
[[ -s $tmp/port ]] || fail "fixture server did not start"
export VPHONE_ASSET_BASE="http://127.0.0.1:$(<"$tmp/port")"
unset TAP_REPO VPHONE_REPO

run() { zsh "$script" "$@" --repo octo/vphone --tap acme/tap; }

# 1. Both casks match the fixtures (notarized asset present).
out="$tmp/o1"
run 1.0.0 --out "$out" > "$tmp/stdout" || fail "render 1.0.0"
diff "$fx/expected/notarized-launchpad.rb" "$out/Casks/vphone-launchpad.rb" || fail "launchpad cask differs"
diff "$fx/expected/skills-1.0.0.rb" "$out/Casks/vphone-skills.rb" || fail "skills cask differs"

# 2. Plain zip is used when the notarized asset is absent (404).
out="$tmp/o2"
run 1.0.1 --out "$out" > /dev/null || fail "render 1.0.1"
diff "$fx/expected/plain-launchpad.rb" "$out/Casks/vphone-launchpad.rb" || fail "plain launchpad cask differs"

# 3. A missing asset fails, prints nothing and writes nothing.
out="$tmp/o3"
if run 1.0.2 --out "$out" > "$tmp/stdout3" 2>/dev/null; then fail "missing asset succeeded"; fi
[[ ! -s $tmp/stdout3 && ! -e $out/Casks ]] || fail "missing asset left output"

# 4. A 5xx is not treated as absent.
out="$tmp/o4"
if run 1.0.3 --out "$out" > "$tmp/stdout4" 2>/dev/null; then fail "5xx succeeded"; fi
[[ ! -s $tmp/stdout4 && ! -e $out/Casks ]] || fail "5xx left output"

# 5. A second --push makes no commit, with no git identity configured.
export HOME="$tmp/home" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
mkdir -p "$HOME"
git init -q --bare -b main "$tmp/remote.git"
git clone -q "$tmp/remote.git" "$tmp/tap" 2> /dev/null
git -C "$tmp/tap" -c user.name=t -c user.email=t@example.com commit -q --allow-empty -m init
git -C "$tmp/tap" push -q origin HEAD:main
run 1.0.0 --push "$tmp/tap" > /dev/null || fail "first --push"
first=$(git -C "$tmp/remote.git" rev-list --count main)
[[ $(git -C "$tmp/remote.git" log -1 --format=%s main) == "vphone 1.0.0" ]] || fail "push subject"
run 1.0.0 --push "$tmp/tap" > /dev/null || fail "second --push"
[[ $(git -C "$tmp/remote.git" rev-list --count main) == $first ]] || fail "second --push committed"

print "brew-cask: five cases passed"
