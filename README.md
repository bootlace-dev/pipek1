# pipek1: Pure Stateless UNIX Cryptographic Filter

A minimal, daemon-less UNIX stream filter implementing BIP-340 Schnorr release signing, Git commit verification, and authenticated stream encryption using Bitcoin and Nostr (`secp256k1`) keypairs.

> **Status:** Draft Specification (v1.9) & Reference Implementation (Phase 1: BIP-340 Schnorr signing, verification, and Git commit plumbing live; Phase 2: Full streaming ChaCha20-Poly1305 engine in active development). Open for peer review, testing, and adversarial critique. Do not use for high-value production secrets without independent verification.

---

## The Problem

1. **The PGP / GnuPG Trap**: OpenPGP relies on fragile background daemons (`gpg-agent`, `dirmngr`), bloated codebases, and vulnerable keyservers (SKS / MIT). As seen in the September 2026 Liquid Network 4,000 BTC incident, attempting to communicate across blockchain and PGP key worlds creates identity confusion and operational failure.
2. **The Root Key Catastrophe**: As observed by cryptographer Constant regarding Nostr identity compromise:
   > *"If you leak the root key, all you can do is cry."*
   Relying on daily operational use of master root seeds exposes sovereign wealth to malware and physical compromise.
3. **The NIP-44 Ceiling**: Nostr's native payload encryption (NIP-44) is capped at 64 KiB. It cannot handle multi-gigabyte ISOs, software release archives, or continuous standard I/O UNIX pipelines.

---

## The `pipek1` Architecture

* **Zero Daemons**: Pure stateless filter (`cat data | pipek1 [sign|verify|encrypt|decrypt] > out`). Zero background sockets, zero keyrings.
* **Bounded RAM Invariant**: Strictly bounded resident memory ($\le 16\text{ MiB}$) on arbitrary gigabyte/terabyte streams.
* **Zero Release of Unverified Plaintext (RUP)**: Spool-and-verify engine buffers data in RAM and anonymous encrypted temporary disk space (`O_TMPFILE`), aborting with exit code `1` and instant cryptographic erasure on any unauthenticated byte.
* **BIP-85 Subroot Isolation**: Operational keys are derived via BIP-85 Application `128002'` from cold storage. If an operational key leaks, the master root remains untouched—no catastrophe, no crying.

---

## Quickstart & Verification

```bash
# Run the end-to-end golden test vector suite:
./test_demo.sh

# Run C-struct binary alignment verifier:
./vectors/verify_c
```

---

## Specification

The complete, asymptotically audited technical specification is locked in [SPECIFICATION.md](SPECIFICATION.md) (v1.9).

---

## Architecture & Autonomous Implementation

This protocol specification, reference Rust implementation, test suites, and cryptographic test vectors were architected under human direction and autonomously coded, audited, and verified using Google Gemini / Antigravity agentic workflows.

