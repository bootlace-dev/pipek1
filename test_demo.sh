#!/usr/bin/env bash
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
echo "=================================================================="
echo " ALL MVP DEMO ASSERTIONS PASSED (100% OK)"
echo "=================================================================="
