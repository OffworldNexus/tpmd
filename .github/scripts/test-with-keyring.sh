#!/usr/bin/env bash
#
# Run the test suite against a real, *writable* OS credential store.
#
# `tpmd-backend-keyring`'s store-gated tests (`crates/tpmd-backend-keyring/
# tests/device.rs`) need an actual Secret Service that can be written to. A
# headless runner has neither a session bus nor a keyring, so this script makes
# both: a private session bus, and a gnome-keyring daemon whose login keyring it
# creates and unlocks with a throwaway password.
#
# Isolation is the point, not a nicety. The daemon gets its own HOME and its own
# runtime directory, so the script never touches the caller's keyrings and cannot
# be affected by them. That matters because a *locked* keyring is worse than no
# keyring at all: the store raises a prompt instead of failing, and a prompt with
# nobody to answer it hangs forever. The suite is therefore also run under a hard
# timeout, so a hang can never consume a whole CI job's budget.
#
# The suite runs with `TPMD_TEST_KEYRING=require`, which turns "no store on this
# host" into a failure rather than a silently skipped test — the store-gated
# tests self-skip by default so that a developer's headless machine stays
# green, and CI must not accept that as proof.
#
# macOS and Windows runners are logged-in user sessions that already have a
# login keychain / Credential Manager, so CI runs the suite there plainly, also
# with `TPMD_TEST_KEYRING=require` and no setup.

set -euo pipefail

# The throwaway HOME below must not hide the toolchain.
cargo_home=${CARGO_HOME:-$HOME/.cargo}
rustup_home=${RUSTUP_HOME:-$HOME/.rustup}
suite_timeout=${TPMD_TEST_TIMEOUT:-900}

if ! command -v gnome-keyring-daemon >/dev/null 2>&1; then
  echo "no gnome-keyring: install it (apt-get install gnome-keyring)," >&2
  echo "or run the suite with TPMD_TEST_KEYRING=0 to skip the store-gated tests" >&2
  exit 1
fi

export TPMD_TEST_KEYRING=require

exec dbus-run-session -- bash -euo pipefail -c '
  export HOME=$(mktemp -d)
  export XDG_RUNTIME_DIR="$HOME/run"
  mkdir -p "$HOME/.local/share/keyrings" "$XDG_RUNTIME_DIR"
  chmod 700 "$XDG_RUNTIME_DIR"
  export CARGO_HOME='"$cargo_home"' RUSTUP_HOME='"$rustup_home"'

  # No keyring exists yet, so this both creates the login keyring and unlocks it;
  # the password is throwaway and nothing else ever sees this store.
  printf "%s\n" "tpmd-ci-keyring" \
    | gnome-keyring-daemon --components=secrets --daemonize --unlock \
        --control-directory="$XDG_RUNTIME_DIR/keyring"

  # The daemon claims the bus name asynchronously; a race here would look like a
  # missing keyring and be reported as a failure.
  for _ in $(seq 1 40); do
    if gdbus call --session --dest org.freedesktop.DBus \
        --object-path /org/freedesktop/DBus \
        --method org.freedesktop.DBus.NameHasOwner org.freedesktop.secrets \
        2>/dev/null | grep -q true; then
      break
    fi
    sleep 0.25
  done

  timeout --kill-after=10 '"$suite_timeout"' cargo test --workspace --all-targets

  # The other build mode this project ships: the packaging split, where the daemon
  # contains no backend above the dummy and every rung above it is a plugin loaded
  # at run time. It has its own feature set and its own test
  # (crates/tpmd/tests/plugin_backends.rs), which loads the *shipped* keyring shim
  # and opens the shared store through it. Running it here, beside the keyring this
  # script just made writable, is the difference between asserting that the rung is
  # offered and asserting nothing at all.
  timeout --kill-after=10 '"$suite_timeout"' \
    cargo test -p tpmd --no-default-features --features loadable-backends --all-targets
'
