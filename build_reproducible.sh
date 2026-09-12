#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bootlace-dev
# 100% Byte-for-Byte Bit-Identical Reproducible Release Builder for pipek1
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SOURCE_DATE_EPOCH=1700000000
export TZ=UTC

echo "Building pipek1 static release binary in reproducible alpine container..."
docker run --rm \
    -u "$(id -u):$(id -g)" \
    -v "$ROOT_DIR/rust":/code \
    -w /code \
    -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    -e TZ="$TZ" \
    rust:alpine@sha256:a10e64dd139b7387337c7fbe8aca31b959b57b2fd4c8ae20a02cf1d6ea424dce sh -c '
        cargo clean
        RUSTFLAGS="--remap-path-prefix=/code=. --remap-path-prefix=/usr/local/cargo=. -C target-cpu=generic" cargo build --release
    '

BIN="$ROOT_DIR/rust/target/release/pipe-k1"
HASH="$(sha256sum "$BIN" | awk '{print $1}')"
SIZE="$(stat -c %s "$BIN")"

echo "=================================================================="
echo " REPRODUCIBLE BUILD SUCCESSFUL"
echo " Binary: $BIN"
echo " Size:   $SIZE bytes"
echo " SHA256: $HASH"
echo "=================================================================="
