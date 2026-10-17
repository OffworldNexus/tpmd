#!/bin/sh
# Build the daemon and make it the bundle's executable.
#
# Xcode's CodeSign step runs *after* every build phase, so installing the binary
# here is what gets it signed with the target's entitlements and the bundle's
# embedded provisioning profile. A launcher that exec'd a separately signed
# binary would not do: the entitlement lives on the executable.
set -eu

# rustup installs here, and Xcode's build environment does not put it on PATH.
PATH="$HOME/.cargo/bin:$PATH"
export PATH

# SRCROOT is packaging/macos, so the workspace is two directories up.
WORKSPACE="$(cd "${SRCROOT}/../.." && pwd)"

# Which binary becomes the agent. The daemon by default; the validation script
# points this at a *test* binary so the device-gated tests can run inside the
# only thing that is allowed near the enclave — a signed bundle.
BINARY="${TPMD_BUNDLE_BINARY:-tpmd}"
BIN_NAME="$(basename "$BINARY")"

if [ -n "${TPMD_BUNDLE_BINARY:-}" ] && [ "${TPMD_BUNDLE_BINARY#/}" != "${TPMD_BUNDLE_BINARY}" ]; then
  # An explicit *path* to whatever binary should become the agent. The device
  # tests use this to put a prebuilt test binary inside the only thing allowed
  # near the enclave; the default path below builds the daemon.
  echo "note: installing the binary named by TPMD_BUNDLE_BINARY"
  BIN_PATH="${TPMD_BUNDLE_BINARY}"
else
  echo "note: building ${BIN_NAME} from ${WORKSPACE}"
  cd "$WORKSPACE"
  cargo build --release --bin "$BIN_NAME"
  BIN_PATH="${WORKSPACE}/target/release/${BIN_NAME}"
fi

echo "note: installing ${BIN_PATH} into ${TARGET_BUILD_DIR}/${EXECUTABLE_PATH}"
install -m 0755 "$BIN_PATH" "${TARGET_BUILD_DIR}/${EXECUTABLE_PATH}"
