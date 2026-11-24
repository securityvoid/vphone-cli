# Homebrew tap

Install Launchpad, the `vphone-launchpad-cli` command and the repository's agent skills with one `brew install --cask` from the `Lakr233/tap` Homebrew tap.

## Install

```sh
brew tap Lakr233/tap
brew trust Lakr233/tap
brew install --cask Lakr233/tap/vphone-launchpad
```

Homebrew refuses to load casks from a tap you have not trusted, and Launchpad depends on the skills cask, so `brew trust` is required.

This installs:

- `vphone-launchpad.app`
- `vphone-launchpad-cli`, linked onto your `PATH`
- the three agent skills, linked into `~/.claude/skills` and `~/.codex/skills`, through the `vphone-skills` cask that Launchpad depends on

Then open Launchpad once for Host Setup and install the matching `VPhone.bundle`:

```sh
vphone-launchpad-cli bundle install-release <version>
```

`<version>` is the version of the Launchpad you installed. `brew info --cask Lakr233/tap/vphone-launchpad` prints this command with the version filled in.

Upgrade and uninstall:

```sh
brew upgrade --cask Lakr233/tap/vphone-launchpad
brew uninstall --cask Lakr233/tap/vphone-launchpad
```

Uninstalling removes the app and the command. The skills stay installed; to remove the skill links too, run `brew uninstall --cask Lakr233/tap/vphone-skills`.

## Set up the tap (maintainers)

The tap is the repository `Lakr233/homebrew-tap`. Until it exists and a release has published to it, the commands above fail. Publishing is off until you set `TAP_REPO`.

1. Create a public repository `Lakr233/homebrew-tap` with a `main` branch (add a README so it is not empty).
2. Create a fine-grained personal access token. Limit it to that one repository and give it **Contents: Read and write** only.
3. In the `Lakr233/vphone-cli` settings under **Secrets and variables > Actions**, add the repository variable `TAP_REPO` with the value `Lakr233/homebrew-tap` and the repository secret `TAP_TOKEN` with the token.
4. Publish a release. After the Launchpad and skills assets are uploaded, the `tap` job writes `Casks/vphone-launchpad.rb` and `Casks/vphone-skills.rb` into the tap repository in one commit.

With `TAP_REPO` unset the `tap` job is skipped and the rest of the release workflow is unchanged.

To publish a release that already exists, for example the first one after creating the tap, check out the tap repository and run the script. It needs only `curl` and `shasum`, and reads public release assets.

```sh
git clone https://github.com/Lakr233/homebrew-tap
zsh scripts/brew-cask.zsh <tag> --tap Lakr233/tap --push homebrew-tap
```

- `--tap` is the tap name, `Lakr233/tap` for the repository `Lakr233/homebrew-tap`. It defaults to `TAP_REPO`.
- `--repo <owner/name>` takes the assets from another repository (default: `VPHONE_REPO`, else `Lakr233/vphone-cli`). Use it with your own `--tap` to publish a fork.
- Without `--push`, add `--out <dir>` to write the casks to a directory (default `.build/brew`) and review them first.
- `--push` stages the two cask files, commits `vphone <tag>` unless nothing changed, and pushes. Run it again after a rejected push to publish.

The release must contain the Launchpad zip (the notarized zip is used when present) and `vphone-skills-<tag>.zip`.

> [!IMPORTANT]
> The release workflow builds an unsigned Launchpad, and macOS refuses to open it once Homebrew has downloaded it ("damaged and can't be opened"). Attach the signed and notarized zip, `vphone-launchpad-<tag>-notarized.zip`, to the release and run the script again so the cask points at it.
