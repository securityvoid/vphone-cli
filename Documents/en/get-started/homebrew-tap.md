# Homebrew tap

Install Launchpad, the `vphone-launchpad-cli` command and the repository's agent skills with one `brew install --cask` from a Homebrew tap.

## Install

Replace `<owner>/<tap>` with the tap name the maintainer gives you, for example `acme/tap` for the repository `acme/homebrew-tap`.

```sh
brew tap <owner>/<tap>
brew trust <owner>/<tap>
brew install --cask <owner>/<tap>/vphone-launchpad
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

`<version>` is the version of the Launchpad you installed. `brew info --cask <owner>/<tap>/vphone-launchpad` prints this command with the version filled in.

Upgrade and uninstall:

```sh
brew upgrade --cask <owner>/<tap>/vphone-launchpad
brew uninstall --cask <owner>/<tap>/vphone-launchpad
```

Uninstalling removes the app and the command. The skills stay installed; to remove the skill links too, run `brew uninstall --cask <owner>/<tap>/vphone-skills`.

## Run your own tap

A release can publish the casks to a tap repository you own. Publishing is off until you set `TAP_REPO`.

1. Create a public GitHub repository named `homebrew-<name>`, for example `acme/homebrew-tap`, with a `main` branch (add a README so it is not empty).
2. Create a fine-grained personal access token. Limit it to that one repository and give it **Contents: Read and write** only.
3. In the fork or upstream repository settings, add a repository variable `TAP_REPO` with the tap repository (`acme/homebrew-tap`) and a repository secret `TAP_TOKEN` with the token.
4. Publish a release. After the Launchpad and skills assets are uploaded, the `tap` job writes `Casks/vphone-launchpad.rb` and `Casks/vphone-skills.rb` into the tap repository in one commit.

With `TAP_REPO` unset the `tap` job is skipped and the rest of the release workflow is unchanged.

### Publish an existing release

Check out the tap repository and run the script for a release tag. It needs only `curl` and `shasum`, and reads public release assets.

```sh
git clone https://github.com/acme/homebrew-tap
zsh scripts/brew-cask.zsh <tag> --tap acme/tap --push homebrew-tap
```

- `--repo <owner/name>` takes the assets from another repository (default: `VPHONE_REPO`, else `Lakr233/vphone-cli`).
- `--tap` is the tap name, `acme/tap` for the repository `acme/homebrew-tap`. It defaults to `TAP_REPO`.
- Without `--push`, add `--out <dir>` to write the casks to a directory (default `.build/brew`) and review them first.
- `--push` stages the two cask files, commits `vphone <tag>` unless nothing changed, and pushes. Run it again after a rejected push to publish.

The release must contain the Launchpad zip (the notarized zip is used when present) and `vphone-skills-<tag>.zip`.

> [!IMPORTANT]
> The release workflow builds an unsigned Launchpad, and macOS refuses to open it once Homebrew has downloaded it ("damaged and can't be opened"). Attach the signed and notarized zip, `vphone-launchpad-<tag>-notarized.zip`, to the release and run the script again so the cask points at it.
