cask "vphone-skills" do
  version "1.0.0"
  sha256 "789b43df20985e0482617d006883019a212f9c21adbe6d2c2ec1cbe13ad184d7"

  url "https://github.com/octo/vphone/releases/download/#{version}/vphone-skills-#{version}.zip"
  name "vphone-skills"
  desc "Agent skills for vphone"
  homepage "https://github.com/octo/vphone"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on arch: :arm64
  depends_on macos: :sequoia

  binary "Skills/vphone-guest-control", target: "#{Dir.home}/.claude/skills/vphone-guest-control"
  binary "Skills/vphone-guest-control", target: "#{Dir.home}/.codex/skills/vphone-guest-control"
  binary "Skills/authoring-patch-sets", target: "#{Dir.home}/.claude/skills/authoring-patch-sets"
  binary "Skills/authoring-patch-sets", target: "#{Dir.home}/.codex/skills/authoring-patch-sets"
  binary "Skills/kernel-analysis-vphone600", target: "#{Dir.home}/.claude/skills/kernel-analysis-vphone600"
  binary "Skills/kernel-analysis-vphone600", target: "#{Dir.home}/.codex/skills/kernel-analysis-vphone600"
end
