cask "vphone-launchpad" do
  version "1.0.0"
  sha256 "a584e1b352cc659f2502133076d04686dd19c40a603d08a5a22ae1bb3f475c03"

  url "https://github.com/octo/vphone/releases/download/#{version}/vphone-launchpad-#{version}-notarized.zip"
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

  uninstall_postflight_steps do
    run "/bin/echo", print_stdout: true, args: [
      "To also remove the vphone agent skills:",
      "brew uninstall --cask acme/tap/vphone-skills",
    ]
  end

  caveats <<~EOS
    Open Launchpad once to complete Host Setup, then run:
      vphone-launchpad-cli bundle install-release #{version}
  EOS
end
