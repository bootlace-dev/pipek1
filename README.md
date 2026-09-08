# pipek1: Pure Stateless UNIX Cryptographic Filter

A minimal, daemon-less UNIX stream filter implementing BIP-340 Schnorr release signing, Git commit verification, and authenticated stream encryption using Bitcoin and Nostr (`secp256k1`) keypairs.

> **Status:** Specification v0.0.1-rc0 & Reference Implementation (BIP-340 Schnorr release signing, verification, Git commit plumbing, and full streaming ChaCha20-Poly1305 AEAD filter). Asymptotically audited and deterministic build verified. Open for peer review, testing, and adversarial critique. Do not use for high-value production secrets without independent verification.

---

## The Problem

1. **The PGP / GnuPG Trap**: OpenPGP relies on fragile background daemons (`gpg-agent`, `dirmngr`), bloated legacy codebases, and vulnerable keyservers (SKS / MIT). As seen in the September 2026 Liquid Network 4,000 BTC incident, attempting to communicate across blockchain and PGP key worlds creates operational friction and critical communication delays.
2. **The Root Key Catastrophe**: As observed by cryptographer Constant regarding Nostr identity compromise:
   > *"If you leak the root key, all you can do is cry."*
   Relying on daily operational use of master root seeds exposes sovereign wealth to malware and physical compromise.
3. **The NIP-44 Ceiling**: Nostr's native payload encryption (NIP-44) is hard-capped at 64 KiB. It cannot handle multi-gigabyte ISOs, software release archives, or continuous standard I/O UNIX pipelines.

---

## Prior Art & Architectural Novelty

While mature cryptographic primitives exist, the ecosystem has remained fragmented:

* **`age` (X25519)**: Excellent modern file encryption, but strictly tied to Curve25519. It has zero native support for Bitcoin/Nostr (`secp256k1`), zero BIP-85 deterministic key derivation, and cannot leverage hardware cold storage wallets.
* **Nostr Git Tooling (`ngit` / NIP-34)**: Wraps Git commits into Nostr network event JSON blobs pushed over WebSockets to relays. It does not provide a local, daemonless UNIX stream filter or drop-in standard Git porcelain signing (`git commit -S`) on sovereign offline workstations.
* **`pipek1` Synthesis**: The first tool to combine **BIP-85 cold-derived `secp256k1` operational keys**, **Rogaway STREAM-ChaCha20-Poly1305** multi-gigabyte authenticated framing, and **zero-daemon Git/UNIX pipelines** into a single, auditable binary.

---

## The `pipek1` Architecture


* **Zero Daemons**: Pure stateless filter (`cat data | pipek1 [sign|verify|encrypt|decrypt] > out`). Zero background sockets, zero keyrings.
* **Bounded RAM Invariant**: Strictly bounded resident memory ($\le 16\text{ MiB}$) on arbitrary gigabyte/terabyte streams.
* **Zero Release of Unverified Plaintext (RUP)**: Spool-and-verify engine buffers data in RAM and anonymous encrypted temporary disk space (`O_TMPFILE`), aborting with exit code `1` and instant cryptographic erasure on any unauthenticated byte.
* **BIP-85 Subroot Isolation**: Operational keys are derived via BIP-85 Application `128002'` from cold storage. If an operational key leaks, the master root remains untouched—no catastrophe, no crying.
* **Hybrid Entropy Hedging (`--entropy-fd`)**: Protects against backdoored CPU TRNGs (`RDRAND`/`RDSEED`) and VM snapshot clone collisions by mixing kernel entropy with physical coin/dice entropy. Digital signing is 100% deterministic (RFC 6979/BIP-340 synthetic nonces) and mathematically immune to broken hardware RNGs.

---

## Entropy & Hardware RNG Threat Model

Understanding the cryptographic blast radius of host and CPU hardware RNGs:

| Primitive | RNG Dependency | Blast Radius of Backdoored / Broken TRNG | Sovereign Mitigation |
| :--- | :--- | :--- | :--- |
| **`pipek1 sign` / Mode 1 Trailer** | **Zero RNG** | **Zero Impact**. BIP-340 generates synthetic nonces deterministically from $sk \parallel \text{msg}$ via HMAC-SHA256. Secret keys cannot leak. | Built-in mathematical immunity. |
| **BIP-85 Child Derivation** | **Zero RNG** | **Zero Impact**. Pure deterministic derivation from seed mnemonic. | Built-in mathematical immunity. |
| **`pipek1 encrypt` ($E_{priv}$)** | `getrandom(2)` | **In-Flight Ciphertext Exposure**. An attacker predicting $E_{priv}$ can derive $IKM = \text{ECDH}(E_{priv}, R_{pub})$ and decrypt that specific stream. **Root keys and recipient private keys are NEVER exposed**. | Supply `--entropy-fd <N>` to mix physical dice/coin entropy into $E_{priv}$ via tagged hash. |

### Example: Physical Entropy Hedging in Pipelines

```bash
# Mix 100 physical coin flips (or dice rolls) with host CSPRNG into ephemeral stream key:
echo "Classified message" | pipek1 encrypt --recipient "$NPUB" --entropy-fd 3 3<<<"HHTTHTHH...TTHT" > payload.pk
```

## Quickstart & Verification

```bash
# Run the end-to-end golden test vector suite:
./test_demo.sh

# Run the 8-stage adversarial UNIX plumbing & exit-code test suite:
./test_adversarial.sh

# Run the Rust integration test suite:
cargo test --manifest-path rust/Cargo.toml --test cli_tests

# Run C-struct binary alignment verifier:
./vectors/verify_c
```

---

## 100% Deterministic Reproducible Builds

`pipek1` releases achieve byte-for-byte SHA-256 reproducibility via pinned Alpine containerization, path remapping, and fixed `SOURCE_DATE_EPOCH`:

```bash
# Compile bit-identical static release binary:
./build_reproducible.sh

# Target Binary Size: 1,036,912 bytes
# Canonical SHA-256: 7a92cebc4f91fcc103f00731292a95f9f55a706ec9a1d170754a24a79522dd5d
```

---

## Specification

The complete, asymptotically audited technical specification is locked in [SPECIFICATION.md](SPECIFICATION.md) (v0.0.1-rc0).

---

## Architecture & Autonomous Implementation

This protocol specification, reference Rust implementation, test suites, and cryptographic test vectors were architected under human direction and autonomously coded, audited, and verified using Google Gemini / Antigravity agentic workflows.

