#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bootlace-dev

# ==============================================================================
# PIPEK1 MUTUAL CROSS-SIGNING UTILITY
# Generates bidirectional BIP-340 Schnorr cross-attestations between
# Master Identity and a Derived pipek1 Child Key.
# ==============================================================================
set -euo pipefail

PIPEK1="/home/bootlace/dev/pipek1/rust/target/release/pipe-k1"

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <MASTER_SEC_KEY_OR_NSEC> <CHILD_SEC_KEY_OR_NSEC>"
    echo ""
    echo "Example:"
    echo "  $0 nsec1master... nsec1child..."
    exit 2
fi

MASTER_SEC="$1"
CHILD_SEC="$2"

# 1. Resolve Public Keys
MASTER_NPUB=$(PIPEK1_SEC_KEY="$MASTER_SEC" "$PIPEK1" pubkey | grep Npub | awk '{print $2}')
CHILD_NPUB=$(PIPEK1_SEC_KEY="$CHILD_SEC" "$PIPEK1" pubkey | grep Npub | awk '{print $2}')

echo "=================================================================="
echo " MUTUAL BIP-340 CROSS-SIGNING ATTESTATION"
echo "=================================================================="
echo "Master Root Identity : $MASTER_NPUB"
echo "Child Key 0 Identity : $CHILD_NPUB"
echo "Timestamp            : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=================================================================="
echo ""

# 2. Leg 1: Master authorizes Child
STATEMENT_M2C="PIPEK1 ATTESTATION: Master identity $MASTER_NPUB authorizes child key $CHILD_NPUB as legitimate pipek1 testing and release signer under BIP-85."
SIG_M2C=$(echo -n "$STATEMENT_M2C" | PIPEK1_SEC_KEY="$MASTER_SEC" "$PIPEK1" sign | base64 -w 0)

echo "--- LEG 1: MASTER -> CHILD AUTHORIZATION ---"
echo "Statement: $STATEMENT_M2C"
echo "BIP-340 Signature (Base64):"
echo "$SIG_M2C"
echo ""

# 3. Leg 2: Child acknowledges Master
STATEMENT_C2M="PIPEK1 ATTESTATION: Child key $CHILD_NPUB acknowledges derivation from and attests allegiance to master identity $MASTER_NPUB."
SIG_C2M=$(echo -n "$STATEMENT_C2M" | PIPEK1_SEC_KEY="$CHILD_SEC" "$PIPEK1" sign | base64 -w 0)

echo "--- LEG 2: CHILD -> MASTER ACKNOWLEDGMENT ---"
echo "Statement: $STATEMENT_C2M"
echo "BIP-340 Signature (Base64):"
echo "$SIG_C2M"
echo ""

# 4. Verification Check
echo "--- VERIFICATION CHECK ---"
echo -n "$STATEMENT_M2C" | "$PIPEK1" verify --sig <(echo "$SIG_M2C" | base64 -d) --pub "$MASTER_NPUB"
echo "  [OK] Master -> Child Signature Verified"

echo -n "$STATEMENT_C2M" | "$PIPEK1" verify --sig <(echo "$SIG_C2M" | base64 -d) --pub "$CHILD_NPUB"
echo "  [OK] Child -> Master Signature Verified"
echo ""
echo "=================================================================="
echo " Attestation bundle ready for publishing to Nostr or public repo."
echo "=================================================================="
