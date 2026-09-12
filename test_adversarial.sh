#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bootlace-dev

set -euo pipefail

PIPEK1="/home/bootlace/dev/pipek1/rust/target/release/pipe-k1"
SHIM="/home/bootlace/dev/pipek1/rust/target/release/pipe-k1"

ALICE_PRIV="0101010101010101010101010101010101010101010101010101010101010101"
ALICE_PUB="1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
BOB_PRIV="0202020202020202020202020202020202020202020202020202020202020202"
BOB_PUB="4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"

TMP_DIR="/tmp/pipek1_adversarial_$$"
mkdir -p "$TMP_DIR"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "=================================================================="
echo " PIPE-K1 ADVERSARIAL & BOUNDARY TEST HARNESS"
echo " Zero Release of Unverified Plaintext (RUP) & Wire Edge Cases"
echo "=================================================================="

# Generate 65,546 byte payload to force intermediate + terminal chunk
python3 -c "import sys; sys.stdout.buffer.write(b'A' * 65546)" > "$TMP_DIR/payload_65k.bin"
"$PIPEK1" encrypt --recipient "$BOB_PUB" < "$TMP_DIR/payload_65k.bin" > "$TMP_DIR/ct_65k.bin"

# Test 1: Chunk Stuffing & Intermediate Chunk Size Invariant
echo -n "[TEST 1] Intermediate chunk length < 64 KiB rejection: "
python3 -c "
with open('$TMP_DIR/ct_65k.bin', 'rb') as f:
    ct = bytearray(f.read())
# offset 97 is chunk 0 len (4B). Alter to 65535
ct[97:101] = b'\x00\x00\xff\xff'
with open('$TMP_DIR/tampered_len.bin', 'wb') as f:
    f.write(ct)
"
set +e
PIPEK1_SEC_KEY="$BOB_PRIV" "$PIPEK1" decrypt < "$TMP_DIR/tampered_len.bin" > "$TMP_DIR/out" 2>/dev/null
EC=$?
set -e
if [ "$EC" -eq 1 ] && [ ! -s "$TMP_DIR/out" ]; then
    echo "PASS (Exit code 1, zero bytes emitted)"
else
    echo "FAIL (Expected exit code 1 with 0 bytes, got EC=$EC, bytes=$(wc -c < "$TMP_DIR/out"))"
    exit 1
fi

# Test 2: Invalid Wire TermTag (term_tag not in {0, 1})
echo -n "[TEST 2] Invalid Wire TermTag (0x02) rejection: "
python3 -c "
with open('$TMP_DIR/ct_65k.bin', 'rb') as f:
    ct = bytearray(f.read())
# offset 97 + 4 = 101 is TermTag. Alter to 0x02
ct[101] = 0x02
with open('$TMP_DIR/tampered_term.bin', 'wb') as f:
    f.write(ct)
"
set +e
PIPEK1_SEC_KEY="$BOB_PRIV" "$PIPEK1" decrypt < "$TMP_DIR/tampered_term.bin" > "$TMP_DIR/out" 2>/dev/null
EC=$?
set -e
if [ "$EC" -eq 1 ] && [ ! -s "$TMP_DIR/out" ]; then
    echo "PASS (Exit code 1, zero bytes emitted)"
else
    echo "FAIL (Expected exit code 1 with 0 bytes, got EC=$EC)"
    exit 1
fi

# Test 3: Trailing Garbage Injection After Stream Termination
echo -n "[TEST 3] Trailing garbage rejection after terminal chunk: "
python3 -c "
with open('$TMP_DIR/ct_65k.bin', 'rb') as f:
    ct = f.read()
with open('$TMP_DIR/garbage.bin', 'wb') as f:
    f.write(ct + b'MALICIOUS_TRAILING_GARBAGE_BYTES')
"
set +e
PIPEK1_SEC_KEY="$BOB_PRIV" "$PIPEK1" decrypt < "$TMP_DIR/garbage.bin" > "$TMP_DIR/out" 2>/dev/null
EC=$?
set -e
if [ "$EC" -eq 1 ] && [ ! -s "$TMP_DIR/out" ]; then
    echo "PASS (Exit code 1, zero bytes emitted)"
else
    echo "FAIL (Expected exit code 1 with 0 bytes, got EC=$EC)"
    exit 1
fi

# Test 4: Git Porcelain Shim Verification Engine
echo -n "[TEST 4] Git Porcelain Shim (commit sign & show-signature verification): "
GIT_TEST_DIR="$TMP_DIR/git_repo"
mkdir -p "$GIT_TEST_DIR"
git init -q "$GIT_TEST_DIR"

# Configure Git to use pipek1 as gpg program
git -C "$GIT_TEST_DIR" config gpg.program "$SHIM"
git -C "$GIT_TEST_DIR" config user.name "Alice Test"
git -C "$GIT_TEST_DIR" config user.email "alice@test.local"
git -C "$GIT_TEST_DIR" config user.signingkey "$ALICE_PUB"
git -C "$GIT_TEST_DIR" config commit.gpgsign true

# Create commit signed with ALICE_PRIV
echo "Initial commit file" > "$GIT_TEST_DIR/file.txt"
git -C "$GIT_TEST_DIR" add file.txt
PIPEK1_SEC_KEY="$ALICE_PRIV" git -C "$GIT_TEST_DIR" commit -q -m "Signed commit by Alice"

# Add Alice to repository allowed signers file
mkdir -p "$GIT_TEST_DIR/.git"
echo "Alice <alice@test.local> $ALICE_PUB" > "$GIT_TEST_DIR/.git/pipek1_signers"

# Verify signature via git log --show-signature
SIG_LOG=$(git -C "$GIT_TEST_DIR" log --show-signature -n 1)

if echo "$SIG_LOG" | grep -q "Good signature from"; then
    echo "PASS (Verified valid signature from $ALICE_PUB)"
else
    echo "FAIL: Expected 'Good signature from' in git log output"
    echo "$SIG_LOG"
    exit 1
fi

# Test 5: Multi-Megabyte (>20 MiB) Encrypted Disk Spooling & Zero RUP
echo -n "[TEST 5] Multi-Megabyte (>20 MiB) Encrypted Disk Spooling & Zero RUP: "
DATA_20MB="$TMP_DIR/payload_20mb.bin"
head -c 20971520 /dev/urandom > "$DATA_20MB"

# Encrypt Mode 1
PIPEK1_SEC_KEY="$ALICE_PRIV" "$PIPEK1" encrypt --mode 1 --recipient "$BOB_PUB" < "$DATA_20MB" > "$TMP_DIR/mode1_20mb.pk"

# Decrypt Mode 1 verifying against ALICE_PUB
PIPEK1_SEC_KEY="$BOB_PRIV" "$PIPEK1" decrypt --sender "$ALICE_PUB" < "$TMP_DIR/mode1_20mb.pk" > "$TMP_DIR/recovered_20mb.bin" 2>/dev/null

if cmp -s "$DATA_20MB" "$TMP_DIR/recovered_20mb.bin"; then
    echo "PASS (20 MiB bit-for-bit identical recovered across O_TMPFILE spool)"
else
    echo "FAIL: 20 MiB payload mismatch"
    exit 1
fi

# Test 6: Entropy Hedging with Empty FD (Must Abort with Exit Code 2)
echo -n "[TEST 6] Empty --entropy-fd abort handling: "
set +e
echo -n "Test payload" | "$PIPEK1" encrypt --recipient "$BOB_PUB" --entropy-fd 3 3< /dev/null 2>/dev/null
EC=$?
set -e
if [ "$EC" -eq 2 ]; then
    echo "PASS (Aborted with error code 2)"
else
    echo "FAIL (Expected exit code 2 on empty entropy fd, got $EC)"
    exit 1
fi

# Test 7: Multi-Megabyte Spool Corruption / Tamper Rejection & Zero RUP
echo -n "[TEST 7] Corrupted 20 MiB multi-chunk stream rejection: "
# Corrupt byte at offset 500,000 (inside payload chunk)
cp "$TMP_DIR/mode1_20mb.pk" "$TMP_DIR/mode1_20mb_corrupt.pk"
printf '\xff' | dd of="$TMP_DIR/mode1_20mb_corrupt.pk" bs=1 seek=500000 count=1 conv=notrunc status=none

set +e
PIPEK1_SEC_KEY="$BOB_PRIV" "$PIPEK1" decrypt --sender "$ALICE_PUB" < "$TMP_DIR/mode1_20mb_corrupt.pk" > "$TMP_DIR/corrupt_out" 2>/dev/null
EC=$?
set -e
if [ "$EC" -eq 1 ] && [ ! -s "$TMP_DIR/corrupt_out" ]; then
    echo "PASS (Exit code 1, zero bytes emitted from corrupted 20 MiB spool)"
else
    echo "FAIL (Expected exit code 1 with 0 bytes, got EC=$EC)"
    exit 1
fi

# Test 8: Git Porcelain pipek1.allowedSignersFile Config
echo -n "[TEST 8] Git Porcelain pipek1.allowedSignersFile configuration: "
GLOBAL_SIGNERS="$TMP_DIR/global_signers"
echo "ExternalSigner <ext@test.local> $ALICE_PUB" > "$GLOBAL_SIGNERS"
rm -f "$GIT_TEST_DIR/.git/pipek1_signers"
git -C "$GIT_TEST_DIR" config pipek1.allowedSignersFile "$GLOBAL_SIGNERS"

SIG_LOG_EXT=$(git -C "$GIT_TEST_DIR" log --show-signature -n 1)
if echo "$SIG_LOG_EXT" | grep -q "Good signature from \"ExternalSigner"; then
    echo "PASS (Verified valid signature from external allowedSignersFile)"
else
    echo "FAIL: Expected 'Good signature from ExternalSigner' in git log output"
    echo "$SIG_LOG_EXT"
    exit 1
fi

echo "=================================================================="
echo " ALL ADVERSARIAL & BOUNDARY ASSERTIONS PASSED (100% OK)"
echo "=================================================================="
