# The environment the published .deb is built in.
#
# Deliberately the *oldest* supported release: whatever glibc it compiles
# against becomes the floor for the published binary, which is what lets one
# artifact per architecture serve bookworm, trixie, sid, jammy, noble and
# resolute alike.
#
# The Rust toolchain is installed here rather than taken from the distribution,
# because no supported release ships a rustc new enough for this workspace
# (rust-version = "1.98", edition 2024). Pinning it to the declared MSRV also
# turns that declaration into something the build tests instead of something a
# comment claims.

ARG BASE=ubuntu:22.04

FROM ${BASE}

# Declared again below FROM: an ARG before FROM is only in scope for the FROM
# instruction itself, so without this the toolchain would arrive empty here.
ARG RUST_VERSION=1.94.0

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      curl \
      debhelper \
      dpkg-dev \
      fakeroot \
      git \
      lintian \
 && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo

# Pin the toolchain for every rustup invocation in this image. Without it rustup
# honours the repository's `rust-toolchain.toml`, which asks for the floating
# `stable` channel: the "built with the declared MSRV" claim would be false, and
# rustup would try to sync stable into a RUSTUP_HOME that an unprivileged build
# cannot write — which is how this shows up, as an unrelated-looking EACCES.
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}

# Spelled out rather than assembled from ${PATH}: an ENV that expands the
# image's PATH is the sort of thing that works until the one time it does not,
# and the failure is a confusing "rustc: not found" after a successful install.
ENV PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}" \
 && printf 'installed: %s\n' "$(/usr/local/cargo/bin/rustc --version)" \
 && printf 'installed: %s\n' "$(/usr/local/cargo/bin/cargo --version)" \
 && printf 'path: %s\n' "$PATH"

WORKDIR /src
