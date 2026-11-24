#!/bin/zsh
# Render the Homebrew casks for a release tag, optionally committing and
# pushing them to a tap checkout. Uses only public release assets.
set -uo pipefail

usage() {
  print -u2 -r -- "Usage: brew-cask.zsh <tag> [--repo <owner/name>] [--tap <owner/name>] [--out <dir>] [--push <tap-checkout>]"
}
die() { print -u2 -r -- "brew-cask: $1"; exit ${2:-1}; }
usage_die() { print -u2 -r -- "brew-cask: $1"; usage; exit 2; }

skills=(vphone-guest-control authoring-patch-sets kernel-analysis-vphone600)
repo_re='^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$'
tag_re='^[0-9]+\.[0-9]+\.[0-9]+$'

tag="" repo="${VPHONE_REPO:-Lakr233/vphone-cli}" tap="" out=".build/brew" push=""
while (( $# )); do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --repo|--tap|--out|--push)
      (( $# >= 2 )) || usage_die "$1 needs a value"
      case $1 in
        --repo) repo=$2 ;; --tap) tap=$2 ;; --out) out=$2 ;; --push) push=$2 ;;
      esac
      shift 2 ;;
    -*) usage_die "unknown option: $1" ;;
    *) [[ -z $tag ]] || usage_die "unexpected argument: $1"; tag=$1; shift ;;
  esac
done

if [[ -z $tap && -n ${TAP_REPO:-} ]]; then
  tap="${TAP_REPO%%/*}/${${TAP_REPO#*/}#homebrew-}"
fi
[[ -n $tag ]] || usage_die "tag is required"
[[ -n $tap ]] || usage_die "--tap (or TAP_REPO) is required"
[[ $tag =~ $tag_re ]] || usage_die "invalid tag: $tag"
[[ $repo =~ $repo_re ]] || usage_die "invalid --repo: $repo"
[[ $tap =~ $repo_re ]] || usage_die "invalid --tap: $tap"
if [[ -n $push ]]; then
  [[ $(git -C "$push" rev-parse --is-inside-work-tree 2>/dev/null) == true ]] \
    || usage_die "--push is not a git work tree: $push"
  out=$push
fi

base="${VPHONE_ASSET_BASE:-https://github.com/$repo/releases/download/$tag}"
work=$(mktemp -d "${TMPDIR:-/tmp}/brew-cask.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$work"' EXIT

# status <asset>: prints the HTTP status of the asset.
status() { curl -sIL -o /dev/null -w '%{http_code}' "$base/$1"; }
# fetch <asset>: downloads it into $work and prints its sha256.
fetch() {
  curl -fsSL -o "$work/$1" "$base/$1" || die "download failed: $1"
  shasum -a 256 "$work/$1" | awk '{print $1}'
}

launchpad="vphone-launchpad-$tag.zip"
notarized="vphone-launchpad-$tag-notarized.zip"
skills_zip="vphone-skills-$tag.zip"

code=$(status "$notarized") || die "probe failed: $notarized"
case $code in
  200) launchpad_asset=$notarized ;;
  404) launchpad_asset=$launchpad ;;
  *) die "unexpected HTTP $code for $notarized" ;;
esac
# require <asset>: succeeds only when the asset answers 200.
require() {
  local code
  code=$(status "$1") || die "probe failed: $1"
  case $code in
    200) ;;
    404) die "release $tag has no asset: $1" ;;
    *) die "unexpected HTTP $code for $1" ;;
  esac
}
require "$launchpad_asset"
require "$skills_zip"

launchpad_sha=$(fetch "$launchpad_asset") || exit 1
skills_sha=$(fetch "$skills_zip") || exit 1
[[ -n $launchpad_sha && -n $skills_sha ]] || die "sha256 failed"

ver='#{version}'
url_base="https://github.com/$repo/releases/download/$ver"

livecheck_block() {
  cat <<EOF
  livecheck do
    url :url
    strategy :github_latest
  end
EOF
}

render_launchpad() {
  cat <<EOF
cask "vphone-launchpad" do
  version "$tag"
  sha256 "$launchpad_sha"

  url "$url_base/${launchpad_asset//$tag/$ver}"
  name "vphone-launchpad"
  desc "Launchpad for the vphone virtual iPhone"
  homepage "https://github.com/$repo"

$(livecheck_block)

  depends_on arch: :arm64
  depends_on cask: "$tap/vphone-skills"
  depends_on macos: :sequoia

  app "vphone-launchpad.app"
  binary "#{appdir}/vphone-launchpad.app/Contents/MacOS/vphone-launchpad-cli"

  uninstall_postflight_steps do
    run "/bin/echo", print_stdout: true, args: [
      "To also remove the vphone agent skills:",
      "brew uninstall --cask $tap/vphone-skills",
    ]
  end

  caveats <<~EOS
    Open Launchpad once to complete Host Setup, then run:
      vphone-launchpad-cli bundle install-release #{version}
  EOS
end
EOF
}

render_skills() {
  cat <<EOF
cask "vphone-skills" do
  version "$tag"
  sha256 "$skills_sha"

  url "$url_base/vphone-skills-#{version}.zip"
  name "vphone-skills"
  desc "Agent skills for vphone"
  homepage "https://github.com/$repo"

$(livecheck_block)

  depends_on arch: :arm64
  depends_on macos: :sequoia

EOF
  local s d
  for s in $skills; do
    for d in .claude .codex; do
      print -r -- "  binary \"Skills/$s\", target: \"#{Dir.home}/$d/skills/$s\""
    done
  done
  print -r -- "end"
}

mkdir -p "$out/Casks" || die "cannot create $out/Casks"
render_launchpad > "$out/Casks/vphone-launchpad.rb" || die "write failed"
render_skills > "$out/Casks/vphone-skills.rb" || die "write failed"
print -r -- "$out/Casks/vphone-launchpad.rb"
print -r -- "$out/Casks/vphone-skills.rb"

if [[ -n $push ]]; then
  files=(Casks/vphone-launchpad.rb Casks/vphone-skills.rb)
  git -C "$push" add -- $files || die "git add failed"
  if ! git -C "$push" diff --cached --quiet -- $files; then
    git -C "$push" \
      -c user.name='github-actions[bot]' \
      -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
      commit -q -m "vphone $tag" -- $files || die "git commit failed"
  fi
  git -C "$push" push || die "git push failed"
fi
