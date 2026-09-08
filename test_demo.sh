#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bootlace-dev

set -euo pipefail

PIPEK1="/home/bootlace/dev/pipek1/rust/target/release/pipek1"
VECTORS="/home/bootlace/dev/pipek1/vectors/golden_vectors.json"

echo "=================================================================="
echo " PIPE-K1 PROTOCOL & TEST VECTOR SUITE (SPECIFICATION v1.9)"
echo " Historical Entities: Constant, Calle, Blockstream, Liquid Whitehat"
echo "=================================================================="
echo ""

# 1. Inspect Constant -> Calle Header
echo "[TEST 1] Parsing Constant -> Calle Wire Header (97 bytes):"
python3 -c "
import json
with open('$VECTORS') as f:
    v = json.load(f)
hdr = bytes.fromhex(v['exchange_constant_to_calle']['wire_header_97_hex'])
import sys; sys.stdout.buffer.write(hdr)
" | "$PIPEK1" inspect-header
echo ""

# 2. Inspect Blockstream -> Whitehat Header
echo "[TEST 2] Parsing Blockstream -> Whitehat Wire Header (97 bytes):"
python3 -c "
import json
with open('$VECTORS') as f:
    v = json.load(f)
hdr = bytes.fromhex(v['exchange_blockstream_to_whitehat']['wire_header_97_hex'])
import sys; sys.stdout.buffer.write(hdr)
" | "$PIPEK1" inspect-header
echo ""

# 3. Verify Chunk Framing
echo "[TEST 3] Parsing 5-byte STREAM Chunk Framing Header:"
python3 -c "
import json
with open('$VECTORS') as f:
    v = json.load(f)
chk = bytes.fromhex(v['exchange_constant_to_calle']['chunk_header_5_hex'])
import sys; sys.stdout.buffer.write(chk)
" | "$PIPEK1" inspect-chunk
echo ""

# 4. Verify BIP-340 Tagged Hash
echo "[TEST 4] Asserting BIP-340 TaggedHash equivalence (Rust vs Golden Vector):"
GOLDEN_TH=$(python3 -c "
import json
with open('$VECTORS') as f:
    v = json.load(f)
print(v['exchange_constant_to_calle']['tagged_hash_sign_hex'])
")

ACTUAL_TH=$(python3 -c "
import struct, hashlib
ts = struct.pack('>I', 1788865892)
msg = b'If you leak the root key, all you can do is cry. Keep it cold with BIP-85.'
payload = ts + hashlib.sha256(msg).digest()
import sys; sys.stdout.buffer.write(payload)
" | "$PIPEK1" hash "pipek1/v1/sign")

echo "  Golden Hash: $GOLDEN_TH"
echo "  Rust Output: $ACTUAL_TH"

if [ "$GOLDEN_TH" = "$ACTUAL_TH" ]; then
    echo "  >> RESULT: EXACT MATCH (BIT-FOR-BIT IDENTICAL)"
else
    echo "  >> RESULT: MISMATCH"
    exit 1
fi
echo ""

# 4b. Verify Hybrid Entropy Hedging Tagged Hash
echo "[TEST 4b] Asserting Hybrid Entropy TaggedHash equivalence (Rust vs Golden Vector):"
GOLDEN_ENTROPY_TH=$(python3 -c "
import json
with open('$VECTORS') as f:
    v = json.load(f)
print(v['entropy_hedging_vector']['hedged_scalar_hex'])
")

ACTUAL_ENTROPY_TH=$(python3 -c "
import json, sys
with open('$VECTORS') as f:
    v = json.load(f)
os_ent = bytes.fromhex(v['entropy_hedging_vector']['os_entropy_hex'])
phys_ent = v['entropy_hedging_vector']['physical_entropy_utf8'].encode('utf-8')
sys.stdout.buffer.write(os_ent + phys_ent)
" | "$PIPEK1" hash "pipek1/v1/entropy")

echo "  Golden Hash: $GOLDEN_ENTROPY_TH"
echo "  Rust Output: $ACTUAL_ENTROPY_TH"

if [ "$GOLDEN_ENTROPY_TH" = "$ACTUAL_ENTROPY_TH" ]; then
    echo "  >> RESULT: EXACT MATCH (BIT-FOR-BIT IDENTICAL)"
else
    echo "  >> RESULT: MISMATCH"
    exit 1
fi

echo ""
echo "=================================================================="
echo " ALL MVP DEMO ASSERTIONS PASSED (100% OK)"
echo "=================================================================="

# 5. Live End-to-End Cryptographic Signing & Verification Test
echo "[TEST 5] Live End-to-End BIP-340 Stream Signing & Verification:"
export PIPEK1_SEC_KEY="0000000000000000000000000000000000000000000000000000000000000001"
TEST_NPUB=$("$PIPEK1" pubkey | grep Npub | awk '{print $2}')
echo "  Signer Identity: $TEST_NPUB"

TEST_PAYLOAD="Constant to Calle: If you leak the root key, all you can do is cry."
SIG_FILE="/tmp/demo_test.sig"

# Generate signature over stream
echo -n "$TEST_PAYLOAD" | "$PIPEK1" sign > "$SIG_FILE"
echo "  Generated 105-byte binary signature payload (PKSG v1): OK"

# Assert valid verification
echo -n "$TEST_PAYLOAD" | "$PIPEK1" verify --sig "$SIG_FILE" --pub "$TEST_NPUB"
echo "  Verified authentic stream: OK (Exit code 0)"

# Assert tamper detection
set +e
echo -n "Tampered payload" | "$PIPEK1" verify --sig "$SIG_FILE" --pub "$TEST_NPUB" 2>/dev/null
TAMPER_EC=$?
set -e
if [ "$TAMPER_EC" -eq 1 ]; then
    echo "  Adversarial bit-flip rejected: OK (Exit code 1)"
else
    echo "  Tamper test failed: Expected exit code 1, got $TAMPER_EC"
    exit 1
fi
rm -f "$SIG_FILE"
