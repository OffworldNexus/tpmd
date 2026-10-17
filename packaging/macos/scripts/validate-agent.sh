#!/bin/sh
# Validate the macOS agent end to end, from the only place it can work.
#
# The agent must run as a per-user LaunchAgent in the Aqua session: that is where
# the login keychain — and with it the Secure Enclave — lives. This script
# installs the template plist with real paths, starts it, asks the daemon what it
# is, walks the toy's key lifecycle against it, and then takes it all back out.
#
# Usage: validate-agent.sh [path/to/tpmd.app]
#
# Set TPMD_TEST_SE=require in the environment of anything that runs inside the
# agent to turn "no enclave here" from a skip into a failure.

set -eu

APP="${1:-packaging/build/tpmd.app}"
STATE_DIR="${TPMD_STATE_DIR:-$HOME/Library/Application Support/tpmd}"
SOCKET="$STATE_DIR/tpmd.sock"
LOG="${TPMD_LOG:-/tmp/tpmd-agent.log}"
LABEL="nexus.offworld.tpmd"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
DOMAIN="gui/$(id -u)"

if [ ! -x "$APP/Contents/MacOS/tpmd" ]; then
  echo "validate-agent: no executable in $APP (build it with: fastlane bundle_agent)" >&2
  exit 2
fi
EXECUTABLE="$APP/Contents/MacOS/tpmd"
mkdir -p "$STATE_DIR"

echo "== entitlements of the agent =="
codesign -d --entitlements - "$EXECUTABLE" 2>&1 | tr -d '\n' | sed 's/></>\n</g' | grep -A1 -E "keychain-access-groups|application-identifier" || true

echo "== installing $PLIST =="
sed -e "s|__TPMD_EXECUTABLE__|$EXECUTABLE|" \
    -e "s|__TPMD_SOCKET__|$SOCKET|" \
    -e "s|__TPMD_STATE_DIR__|$STATE_DIR|" \
    -e "s|__TPMD_LOG__|$LOG|" \
    "$(dirname "$0")/../nexus.offworld.tpmd.plist" > "$PLIST"

launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
launchctl bootstrap "$DOMAIN" "$PLIST"

# Wait for the socket rather than guessing at a sleep.
i=0
while [ ! -S "$SOCKET" ]; do
  i=$((i + 1))
  if [ "$i" -gt 100 ]; then
    echo "validate-agent: the agent never bound $SOCKET; last log lines:" >&2
    tail -20 "$LOG" >&2 || true
    exit 1
  fi
  sleep 0.2
done

echo "== status =="
"$EXECUTABLE" status --socket "$SOCKET"

echo "== what this machine remembers =="
"$EXECUTABLE" backend --state-dir "$STATE_DIR" || true

echo "== the toy's lifecycle, against the bundled agent =="
# `tpmd-demo run` starts its *own* daemon (the unsigned one next to it), which
# would have no enclave at all — so the lifecycle is walked step by step against
# the agent that is actually running.
FINGERPRINT=$(cargo run -q -p tpmd-demo -- --socket "$SOCKET" provision 2>/dev/null | grep -E '^0[23][0-9a-f]{64}$' | tail -1 || true)
if [ -z "$FINGERPRINT" ]; then
  echo "validate-agent: the toy provisioned no key" >&2
  exit 1
fi
echo "fingerprint: $FINGERPRINT"
cargo run -q -p tpmd-demo -- --socket "$SOCKET" describe "$FINGERPRINT"
cargo run -q -p tpmd-demo -- --socket "$SOCKET" sign "$FINGERPRINT" "validate-agent"

echo "== the key re-opens after the agent restarts =="
# The whole reason the key's label is recorded: a restart is a new process, and
# the enclave key has to be found again in the keychain — not re-minted (that
# would re-key the device) and not lost.
launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
launchctl bootstrap "$DOMAIN" "$PLIST"
i=0
while [ ! -S "$SOCKET" ]; do
  i=$((i + 1))
  [ "$i" -gt 100 ] && { echo "validate-agent: the agent did not come back" >&2; exit 1; }
  sleep 0.2
done
cargo run -q -p tpmd-demo -- --socket "$SOCKET" describe "$FINGERPRINT"
cargo run -q -p tpmd-demo -- --socket "$SOCKET" sign "$FINGERPRINT" "after-restart"

echo "== tearing the agent back out =="
launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
rm -f "$PLIST"
echo "ok: the agent ran, served an enclave key and signed with it"
