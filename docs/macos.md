# The macOS agent (Secure Enclave)

`tpmd` on macOS runs as a **per-user agent** whose strongest rung is the Secure
Enclave: P-256 keys that never leave hardware, at security level `hardware`. The
login keychain provides the `keyring` rung (WVR-151's universal backend). There is
**no `sealed` rung on macOS** — what one would even be is an open question, and
WVR-154 owns it; until then a Mac whose enclave is unusable falls to `keyring`,
which is below the default `sealed` floor, so clients are refused unless they
consent with `allow_below_floor`. That is the intended "never silently weaken"
behaviour, not a bug.

## The three platform restrictions

Each of these was measured on the M1 rig, and each wasted real time before it was
understood. None of them is worked around: a workaround would be a lie about what
the level means.

### 1. The agent must run from a signed bundle, under a provisioned identifier

Creating a *persistent* Secure Enclave key needs the keychain to store it, and the
keychain refuses any bundle it cannot place:

* without a **provisioning profile** the entitlement is not authorised, and macOS
  kills the process at exec (AMFI) rather than letting it try;
* with a profile but a bundle identifier the team has **not provisioned**, the
  store is refused with `errSecMissingEntitlement (-34018)` — which reads like a
  signing bug and is one. `nexus.offworld.tpmd` works; a name nobody provisioned
  does not, even though the signature looks perfect.

This is why the agent is a `.app` whose **executable is the daemon itself**
(`packaging/macos`): the entitlement lives on the executable, so a launcher that
exec'd a separately signed binary would lose it. The identifier comes from
configuration (`TPMD_BUNDLE_ID`), because it is a deployment's business, not the
repository's.

### 2. It must run in the Aqua session

An SSH login lands in launchd's `Background` domain, where the login keychain is
unreachable — so the agent is started by launchd as a per-user LaunchAgent
(`packaging/macos/nexus.offworld.tpmd.plist`). Note the asymmetry that makes a
naive liveness check useless: an **ephemeral** enclave key can be created from any
session, while **keeping** one cannot. The backend therefore probes by *storing*.

### 3. Signing happens in the Aqua session too

`codesign` from SSH fails with `errSecInternalComponent`, because the key's
authorisation belongs to the GUI session. Build the bundle from a Terminal on the
desktop (or any process in `gui/<uid>`).

## What the backend does

| Operation | Behaviour |
| --- | --- |
| `provision` | Creates a P-256 key in the Secure Enclave, stored in the data protection keychain under a random label; refuses any level but `hardware` and any algorithm but ECDSA P-256/SHA-256. If the platform ever hands out the private half, the key is deleted and the operation refused — non-exportability is the whole claim. |
| `identify` | Reads the `se_keys` row and reports the level actually achieved. |
| `sign` | Hashes the message once (SHA-256) and asks the enclave to sign that digest; the DER it returns is converted to raw `r ‖ s` at this boundary, as protocol §10 requires. |
| `destroy` | Removes the keychain item and then the row: a row without its key is key loss the caller can act on, a key without its row is an orphan nobody can address. |

No user-presence policy is imposed — `privateKeyUsage` with
`AccessibleWhenUnlockedThisDeviceOnly` and no biometry or passcode requirement. A
prompt on an unattended agent is a hang, not a security win.

### Where a key's state lives

* the **private key**: the login keychain, non-exportable, inside the enclave;
* the **label** that finds it again, the fingerprint, level and creation time: the
  `se_keys` table in the shared store (`m20260101_000006_create_se_keys`).

Nothing else. There is no operation that can copy a private key out.

## When it cannot serve

The backend classifies what it finds as `Open`, `Closed` or `Gone`, and the
difference decides whether a client waits or is told no:

| What happened | `OSStatus` | Reported as | What fixes it |
| --- | --- | --- | --- |
| Enclave and keychain both work | — | `Open` | — |
| Keychain locked, or the session cannot interact with it | `-25308`, `-25293` | `Closed` — waitable | the user unlocks the login keychain |
| Bundle identifier not provisioned | `-34018` | `Gone` — `backend_unavailable` | re-sign with a provisioned App ID |
| No enclave at all (Intel Mac without one, or a VM) | any other | `Gone` | hardware |

A `Gone` verdict is not re-probed: the process cannot change its own signature
while it runs, so asking again would only ever get the same answer. A `Closed` one
is, because the user unlocks keychains all the time — and if the storage question
has never been answered successfully, the next probe asks it again.

`tpmd status` says which of these is true and names the store
(`macos-se (secure-enclave)`), and `tpmd backend` says what this machine
remembers choosing.

## Recovery

* **`store: closed`** — unlock the login keychain (Keychain Access, or
  `security unlock-keychain ~/Library/Keychains/login.keychain-db`) and the agent
  picks it up on its own; no restart is needed.
* **`reject backend_unavailable`** — the agent is running from something the
  keychain will not accept: check `codesign -d --entitlements - <agent>` for
  `keychain-access-groups`, and that the identifier appears in a provisioning
  profile. Then run `packaging/macos/scripts/validate-agent.sh`.
* **key loss** — a row whose keychain item is gone (someone removed the key, or
  restored a store file onto a different Mac). The key is gone for good: re-pair.
  The daemon never replaces a lost key with a weaker one.
* **the enclave is unavailable** — macOS reports it and the agent does not
  pretend otherwise. On a Mac without an enclave the ladder falls to `keyring`,
  which needs explicit consent below the `sealed` floor.

## Building and validating it

```sh
# On the Mac, in the Aqua session (see restriction 3):
cd packaging && bundle install
bundle exec fastlane bundle_agent        # DEVELOPMENT_TEAM and TPMD_BUNDLE_ID from .env
```

`packaging/fastlane/.env.default` lists every setting; copy it to `.env` and fill
it in (it is git-excluded). Locally Xcode's automatic signing mints and embeds the
profile, so a developer needs nothing but the team id; in CI an App Store Connect
API key (`ASC_KEY_ID`, `ASC_ISSUER_ID`, `ASC_KEY_CONTENT`) does the same headless.
Nothing here runs on the push/PR path.

Then, from anywhere:

```sh
packaging/macos/scripts/validate-agent.sh packaging/build/tpmd.app
```

It installs the LaunchAgent, asks the daemon what it is, walks the toy's
life-cycle against it, **restarts the agent and re-opens the same key**, and takes
it all back out. The device-gated tests need the same thing, so they are run from
inside the bundle too — build the `device` test binary with cargo, put it in a copy
of the bundle as `Contents/MacOS/tpmd`, re-sign that copy with the same
entitlements, and run it with `TPMD_TEST_SE=require`, which turns "no enclave
here" from a skip into a failure.

## Evidence from the M1 rig

Recorded 2026-10-18, on the offered Apple Silicon Mac (macOS 26.5, arm64), with the
bundle built as described above:

| Check | Result |
| --- | --- |
| `tpmd status` from the bundled agent | `backend: macos-se (secure-enclave)`, `levels: [hardware] (achieved hardware)`, `store: open` |
| Toy life-cycle against that agent | a key provisioned at `hardware` (`034e9984…`), signed (`86b6553c…`, 64 bytes raw), and re-opened after an agent restart |
| Selection record (WVR-153) | `selection: not recorded yet` before first use → `chosen 0 seconds ago — the strongest backend that could serve here` after it |
| Device tests inside the bundle, `TPMD_TEST_SE=require` | **5 passed, 0 failed** — including independent `p256` verification of a signature, both negative controls, a key surviving a backend restart, principal scoping, and a `sealed` request being refused |
| Crypto pipeline measured separately | transcript digest `258a08d9…21c0` matches the document; DER → raw `r ‖ s` verifies under `p256`; private-key export refused; public key → SEC1 compressed (33 B) |
| Entitlements on the built bundle | `keychain-access-groups` and `com.apple.application-identifier` = `58ZY9D9T94.nexus.offworld.tpmd`, profile embedded, signature verifies |
