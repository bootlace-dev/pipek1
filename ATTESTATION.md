# pipek1 Operational Key Delegation & Mutual Cross-Attestation

This document establishes the verified cryptographic link between the primary `@bootlace-dev` root identity and the daily operational `pipek1` release signing key.

---

## Cryptographic Identities

* **Master Root Identity**: `npub1e94hqt3fuu7rvy9rpl85h3339vtn8psgewq4u05r7q4nup2kwp4q0flgay`
* **Operational Child Key 0**: `npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7`
* **Derivation Standard**: BIP-85 Application `128002'` (Index `0'`)
* **Signature Algorithm**: BIP-340 Schnorr over Tagged Hash (`pipek1/v1/sign`)
* **Timestamp**: `2026-09-08T18:00:40Z`

---

## Leg 1: Master Root Authorizes Child Key 0

**Statement**:
```text
PIPEK1 ATTESTATION: Master identity npub1e94hqt3fuu7rvy9rpl85h3339vtn8psgewq4u05r7q4nup2kwp4q0flgay authorizes child key npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7 as legitimate pipek1 testing and release signer under BIP-85.
```

**BIP-340 Schnorr Signature (Base64)**:
```text
UEtTRwFqoE1IyWtwLinnPDYQow/PS8YxKxczhgjLgV4+g/ArPgVWcGpn8mX4iYjPz2IMdg8tHsqa9sW5OS/bYR2hiNzx9Q7/d6BFzJO20bs3ezeZOgVcLTZKdIIxfZl9+lux6XrUPGE4
```

---

## Leg 2: Child Key 0 Acknowledges Master Root

**Statement**:
```text
PIPEK1 ATTESTATION: Child key npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7 acknowledges derivation from and attests allegiance to master identity npub1e94hqt3fuu7rvy9rpl85h3339vtn8psgewq4u05r7q4nup2kwp4q0flgay.
```

**BIP-340 Schnorr Signature (Base64)**:
```text
UEtTRwFqoE1I2z911dKP2J24ugG7bv5n0oavTn4R69s85RS4zrLBDnIsdSu5HqRmts1fCHkD682D9ROp5xxCtdj3HFrJP4/4oQ33oZhrziFDSSpVCJ/AUFRV1rwZK+aKnf0hwp2ouHOi
```

---

## Independent Verification Command

```bash
# Verify Master -> Child authorization:
echo -n "PIPEK1 ATTESTATION: Master identity npub1e94hqt3fuu7rvy9rpl85h3339vtn8psgewq4u05r7q4nup2kwp4q0flgay authorizes child key npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7 as legitimate pipek1 testing and release signer under BIP-85." | \
  pipek1 verify --sig <(echo "UEtTRwFqoE1IyWtwLinnPDYQow/PS8YxKxczhgjLgV4+g/ArPgVWcGpn8mX4iYjPz2IMdg8tHsqa9sW5OS/bYR2hiNzx9Q7/d6BFzJO20bs3ezeZOgVcLTZKdIIxfZl9+lux6XrUPGE4" | base64 -d) \
  --pub "npub1e94hqt3fuu7rvy9rpl85h3339vtn8psgewq4u05r7q4nup2kwp4q0flgay"

# Verify Child -> Master acknowledgment:
echo -n "PIPEK1 ATTESTATION: Child key npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7 acknowledges derivation from and attests allegiance to master identity npub1e94hqt3fuu7rvy9rpl85h3339vtn8psgewq4u05r7q4nup2kwp4q0flgay." | \
  pipek1 verify --sig <(echo "UEtTRwFqoE1I2z911dKP2J24ugG7bv5n0oavTn4R69s85RS4zrLBDnIsdSu5HqRmts1fCHkD682D9ROp5xxCtdj3HFrJP4/4oQ33oZhrziFDSSpVCJ/AUFRV1rwZK+aKnf0hwp2ouHOi" | base64 -d) \
  --pub "npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7"
```
