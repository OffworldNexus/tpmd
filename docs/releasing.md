# Releasing tpmd

This is the procedure an agent (or a human) follows to publish a release. It is
deliberately mechanical: almost everything that can be checked is checked by
`.github/workflows/packaging-deb.yml`, and the parts a person has to decide are
the version number and the words in the tag message.

As of 0.1, **tpmd is distributed by APT only**. The complete release artifact
set is the Debian source package plus the three `.deb`s for `amd64` and `arm64`.
RPM, Arch, Windows and macOS packaging will add their own workflows and
artifacts later; when that happens this document gains a row in the matrix and
the release job waits for those jobs too.

## What the automation does

Pushing a `v*` tag starts `deb packages` (`.github/workflows/packaging-deb.yml`):

1. `version` reads the tag, requires the tag to be of the form `vX.Y.Z`, and
   refuses the release unless `Cargo.toml`'s workspace version is exactly
   `X.Y.Z`.
2. `source` builds the source package from the tagged commit in the pinned
   container, lints it, and publishes it as a workflow artifact.
3. `build` builds the `.deb`s **from that source package**, offline, for
   `amd64` and `arm64`, and lints them.
4. `publish` pushes the `.deb`s and `.dsc` to Cloudsmith's `main` component.
5. `publish-forgejo` pushes the same `.deb`s to the Forgejo mirror's `main`
   component. A run without `FORGEJO_PACKAGES_TOKEN` skips this, as a fork does.
6. `verify` installs from Cloudsmith in a clean container for every supported
   release, and `verify-forgejo` does the same from the mirror: repository
   signature, the split backend packages, the plugin loader, the daemon, and
   the package lifecycle.
7. `release` creates the GitHub release, attaches every artifact and a
   `SHA256SUMS`, and prepends the tag message to GitHub's generated notes.

A tag is only a release if every one of those succeeds. There is no manual
"publish" switch and no repository variable to flip.

### Repository secrets

| Secret | Used by | Purpose |
| --- | --- | --- |
| `CLOUDSMITH_API_KEY` | `packaging-deb.yml` | push to the primary APT repository |
| `FORGEJO_PACKAGES_TOKEN` | `packaging-deb.yml` | push to the mirror; absent means no mirror |
| `OPENROUTER_API_KEY` | `security.yml` | the headless OpenCode model |
| `RELEASE_TOKEN` | `security.yml` | push branches/tags and open/merge the bot PR |

`RELEASE_TOKEN` is a user or fine-grained token, not `GITHUB_TOKEN`: the
organization forbids GitHub Actions from creating pull requests, and a
`GITHUB_TOKEN` push does not start the next workflow. A fine-grained token
needs contents, pull requests, actions and workflows write.

## Before tagging

1. Start from the commit that should be released — normally the tip of
   `develop`. The tag must point at a commit already on `develop`; do not tag a
   feature branch.
2. Decide the version (see below) and make sure the workspace version in the
   root `Cargo.toml` is exactly that version. Every crate inherits it with
   `version.workspace = true`; do not edit individual crate manifests.
3. Make sure CI on that commit is green, including `cargo-deny`.
4. Run the packaging checks locally if the release is unusual (first release,
   a release after a packaging change):

   ```sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace --all-targets -q
   cargo deny check
   ```

## Version numbers

Use SemVer, with the usual 0.x caveat that a minor bump may break.

| Change | Version |
| --- | --- |
| A security fix to dependencies, no API change | patch: `0.1.0` → `0.1.1` |
| Backwards-compatible feature, protocol addition | minor: `0.1.1` → `0.2.0` |
| A breaking wire or API change | minor while 0.x, major after 1.0 |

The protocol version in `tpmd-proto` is separate from the package version. Do
not bump `PROTOCOL_VERSION` for a release that changes no wire bytes.

## The tag

Release tags are **annotated** and named `vMAJOR.MINOR.PATCH`:

```sh
git tag -a v0.1.0 -F /tmp/tag-message.md
git push origin v0.1.0
```

Never use a lightweight tag, never reuse a tag name, never move a tag after it
has been pushed, and never delete a published release. A mistake is fixed by
releasing the next patch.

### Tag message contract

The tag message is the release notes. The first line is the release **title**;
the rest is the hand-written body:

```text
tpmd 0.1.0

The first stable release of the tpmd local key agent.

## Highlights

- One `tpmd` binary and one package per backend above the built-in `file`
  floor, chosen at run time and committed on first use.
- A closed credential store is a waitable state, not an error.
- Debian and Ubuntu installs are available from Cloudsmith and the Forgejo
  mirror.

## Security

No new advisories. RUSTSEC-2026-0385 and RUSTSEC-2026-0387 are accepted for
this release and are fixed in 0.1.1.

## Upgrade

    sudo apt-get update
    sudo apt-get install --only-upgrade tpmd

Keys survive an upgrade: `/var/lib/tpmd` is the device identity and neither
`apt remove` nor `apt purge` deletes it.
```

Rules for the text:

* **First line**: `tpmd X.Y.Z` for a normal release, `tpmd X.Y.Z (security)` for
  a security-only patch. Nothing else — the automation uses it verbatim as the
  release name.
* **Body**: start with one or two sentences a user needs. Then use the sections
  that apply, in this order: `## Highlights`, `## Fixes`, `## Security`,
  `## Upgrade`, `## Packaging`. Omit empty sections.
* **Security**: list every RUSTSEC ID the release fixes, with the crate and the
  version change. If the release deliberately ships with accepted advisories,
  say so and say which release fixes them. Never describe an accepted advisory
  as "fixed".
* **Do not** paste a commit list or a `git log`; GitHub appends its generated
  "What's Changed" notes underneath the hand-written body.
* **Do not** claim a platform the release does not ship. As of 0.1 that means
  Debian and Ubuntu on `amd64`/`arm64`, from both repositories.

## Publishing

A human with repository write access pushes the tag with their own credentials:

```sh
git push origin v0.1.0
```

The push event starts the release workflow. Watch it:

```sh
gh run list --workflow packaging-deb.yml --limit 3
gh run watch <run-id> --exit-status
```

An automated agent may not have a token that triggers workflows on a tag push
(`GITHUB_TOKEN` deliberately does not). In that case it creates the tag and
explicitly dispatches the workflow **on the tag ref**, after the tag already
exists:

```sh
gh workflow run packaging-deb.yml --ref v0.1.1
```

The `workflow_dispatch` path is a nightly when run on a branch; on a tag ref it
picks the tag's version and the `main` component, exactly like a pushed tag.

## After the release

Check that both repositories really carry it, from a clean container:

```sh
# Cloudsmith
TPMD_VERIFY_REPO=cloudsmith packaging/deb/verify-install.sh debian:13

# Forgejo
TPMD_VERIFY_REPO=forgejo packaging/deb/verify-install.sh debian:13
```

Then confirm the GitHub release has the title, the body and the assets:

```sh
gh release view v0.1.0
gh release download v0.1.0 --dir /tmp/tpmd-release
(cd /tmp/tpmd-release && sha256sum -c SHA256SUMS)
```

Update Linear: move the release ticket to Done and comment the tag, the workflow
run and the version users can now install. Leave deferred platform tickets in
Backlog with a comment naming this release as the reason they were deferred.

## Security patch releases

The hourly `security` workflow (`.github/workflows/security.yml`) is the normal
way a patch release happens:

1. It runs `cargo deny` against a strict config that drops every `TEMPORARY`
   acceptance (the permanent unmaintained-crate ignores stay).
2. If an advisory is found, it runs headless OpenCode with the OpenRouter model
   to update the affected dependencies and to remove any temporary ignores from
   `deny.toml`. It prefers the highest release that keeps the test suite green,
   including a semver-incompatible bump when that is what the fix requires; it
   does not stop at the advisory's minimum and does not choose a yanked
   version.
3. It runs the test suite, opens and merges a branch through a PR, bumps the
   workspace version to the next patch, tags `vX.Y.Z`, and lets the tag push
   start the normal packaging workflow.
4. The release notes come from the tag message, which lists the RUSTSEC IDs and
   the dependency changes.

A human may also cut a security patch by hand using the procedure above. Do not
edit a released tag to "add" a fix.

### Temporary advisory ignores

`deny.toml` may contain an ignore for an advisory that has no fix yet. It must
carry a comment saying why and which release will remove it. The security
workflow deliberately ignores those ignore entries when it looks for work, so a
temporary acceptance cannot hide a fixable advisory from the bot.

## What not to do

* Do not release from a dirty tree, a feature branch, or a commit that is not on
  `develop`.
* Do not tag to "see what happens". The pipeline publishes to both `main`
  components; a tag is a release users can install.
* Do not publish a stable version by dispatching a *branch* run with a stable
  version. That would put packages on the stable channel without a GitHub
  release or a tag to point at.
* Do not add a platform's artifacts to a release by hand. A platform gets a
  workflow; the release job waits for it.
