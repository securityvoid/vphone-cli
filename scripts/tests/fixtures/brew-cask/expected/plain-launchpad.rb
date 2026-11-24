cask "vphone-launchpad" do
  version "1.0.1"
  sha256 "6bffb404795a55a0c1ae4785d181184948d0fdb20e7398df9a64b6e35ef921ea"

  url "https://github.com/octo/vphone/releases/download/#{version}/vphone-launchpad-#{version}.zip"
  name "vphone-launchpad"
  desc "Launchpad for the vphone virtual iPhone"
  homepage "https://github.com/octo/vphone"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on arch: :arm64
  depends_on cask: "acme/tap/vphone-skills"
  depends_on macos: :sequoia

  app "vphone-launchpad.app"
  binary "#{appdir}/vphone-launchpad.app/Contents/MacOS/vphone-launchpad-cli"

  caveats <<~EOS
    Open Launchpad once to complete Host Setup, then run:
      vphone-launchpad-cli bundle install-release #{version}
  EOS
end
