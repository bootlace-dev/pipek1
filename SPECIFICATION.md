# Design Specification: `pipe-k1` (Stateless UNIX Cryptographic Filter via Secp256k1)

**Codename:** `pipe-k1`  
**Status:** RFC / v0.0.1-rc0 (Asymptotically Audited & Deterministic Build Verified)  
**Target:** Direct drop-in, stateless replacement for GnuPG (`gpg`) across software release signing, git commit authentication, and stream encryption using Bitcoin and Nostr (`secp256k1`) keypairs.  
**Architectural Invariants:**
1. Pure stateless UNIX filter: zero daemons, zero background keyring state, zero database dependencies, zero network sockets compiled in.
2. Strictly bounded memory consumption ($\le 16\text{ MiB}$ resident memory) on arbitrary payload streams (up to multi-terabyte files). Spilled temporary data is locally authenticated and encrypted in-flight using sequential block counters.
3. Zero private key exposure to process tables (`/proc/$PID/cmdline`), environment blocks (`/proc/$PID/environ`), and child process descriptors (`FD_CLOEXEC`). Secret file descriptors and files are closed immediately upon ingestion.
4. Strict domain separation preventing cross-protocol signature replay.
5. Absolute stream completeness: rejection of truncated or trailing-garbage streams (exit code `1`) and zero Release of Unverified Plaintext (RUP) across all decryption and verification pipelines by default.

---

## 1. Cryptographic Primitives & Mathematical Foundations

### 1.1 Mathematical Primitives
* **Curve:** `secp256k1` over field $\mathbb{F}_p$ ($y^2 = x^3 + 7 \pmod p$), base point $G$, curve order $n$.
* **Coordinate Extraction & Point Functions:**
  * $\text{point\_x}(P) \in \mathbb{F}_p$: Extracts the 32-byte big-endian x-coordinate of affine curve point $P = (X, Y)$.
  * $\text{lift\_x}(X)$: Affine decompression function accepting a 32-byte scalar coordinate $X \in \mathbb{F}_p$ ($X < p$). Asserts $c = X^3 + 7 \pmod p$ is a quadratic residue in $\mathbb{F}_p$. Returns the unique point $(X, Y)$ where $Y \pmod 2 = 0$. If $c$ has no square root or $X \ge p$, the input is rejected immediately with exit code `1` (if encountered on wire) or `2` (if passed as local argument).
* **Private Key Parity Negation (BIP-340 Signing Invariant):**
  * Let $sk \in [1, n-1]$ be the private scalar. Compute point $P = sk \cdot G$.
  * If the $Y$-coordinate of $P$ is odd ($Y \pmod 2 \ne 0$), the signing scalar is negated modulo $n$: $sk' = n - sk$. This guarantees the signing key matches the 32-byte x-only public key $X = \text{point\_x}(P)$.
* **Symmetric Cipher:** `AEAD_CHACHA20_POLY1305` (RFC 8439) in a chunked Rogaway STREAM construction.
* **Key Derivation Function:** HKDF-SHA256 (RFC 5869).
* **Header Authentication:** HMAC-SHA256 (RFC 2104).

### 1.2 Key Intake Protocols & Memory Scrubbing
Private keys and seed mnemonics must never be exposed as command-line arguments.

#### Key Intake Vectors
1. **Environment Variables:** `PIPEK1_SEC_KEY` (Bech32 `nsec1...`, 64-char hex scalar, or Base58Check WIF) and `PIPEK1_MNEMONIC` (BIP-39 mnemonic phrase).
2. **File Descriptor:** `--sec-fd <N>` (e.g. `pipek1 sign --sec-fd 3 3<<<"$NSEC"`).
3. **Protected Path:** `--sec-file <path>` (e.g. `/dev/shm/key.sec`).
4. **Deterministic Derivation (BIP-85 Application `128002'`):**
   * Path: `m/83696968'/128002'/<identity>'/<index>'` where `<identity>` and `<index>` are 31-bit unsigned integers ($0 \le i < 2^{31}$).
   * Derivation uses BIP-32 master key derived from BIP-39 mnemonic + passphrase (supplied via `--mnemonic-fd <N>`, `--passphrase-fd <N>`, or `PIPEK1_MNEMONIC`).
   * Entropy extraction per BIP-85: $K = \text{HMAC-SHA512}(\text{Key} = \text{"bip-entropy-from-k"}, \text{Data} = \text{BIP32ChildPrivateKeyScalar}_{32\text{B}})$.
   * **Scalar Extraction & Boundary Rule:** From the 64-byte HMAC output, extract the **first 32 bytes (256 most significant bits)**. If $sk = 0$ or $sk \ge n$, derivation fails hard and exits with code `2`.
5. **Process Environment Scrubbing & Descriptor Hygiene:**
   * **Comprehensive Environment Scrubbing:** Immediately upon ingestion, `pipek1` locates and overwrites the memory occupied by both `PIPEK1_SEC_KEY` and `PIPEK1_MNEMONIC` in the process environment block (`environ`) with zeros (`memset_s` / explicit volatile wipe) and calls `prctl(PR_SET_DUMPABLE, 0)` on Linux to restrict unprivileged `/proc/$PID/environ` inspection, ptrace attachment, and core-dump generation.
   * **Descriptor Closure & File Hygiene:** All secret-intake file descriptors (`--sec-fd`, `--mnemonic-fd`, `--passphrase-fd`) as well as file handles opened via `--sec-file` are opened with `O_CLOEXEC` / `FD_CLOEXEC` and are **immediately closed (`close(fd)`)** once key contents have been read into resident memory.
   * All scalar registers, mnemonic buffers, and intermediate ECDH points are allocated in `mlock`-pinned memory and explicitly wiped on drop (`ZeroizeOnDrop`).

---

## 2. Wire Formats & Streaming Protocols

### 2.1 Detached Digital Signatures (`pipe-k1 sign` / `pipe-k1 verify`)
To prevent signature replay across software releases, Nostr events (NIP-01), and Bitcoin Taproot commits, signatures use BIP-340 tagged hashes:

$$\text{Tag} = \text{"pipe-k1/v1/sign"}$$
$$\text{TagHash} = \text{SHA-256}(\text{Tag})$$
$$\text{PayloadDigest} = \text{Streaming-SHA-256}(\text{data})$$
$$\text{Timestamp} = \text{Unix epoch seconds (4B big-endian)}$$
$$\text{MessageDigest} = \text{SHA-256}(\text{TagHash} \parallel \text{TagHash} \parallel \text{Timestamp} \parallel \text{PayloadDigest})$$

#### Unified Signature Wire Payload (Exact 105 Bytes Fixed)
```text
+---------------+---------------+-------------------+----------------------+
| Magic (4B)    | Version (1B)  | Timestamp (4B BE) | Signer Pubkey (32B)  |
| "PKSG"        | 0x01          | uint32 seconds    | x-only curve point   |
+---------------+---------------+-------------------+----------------------+
| BIP-340 Schnorr Signature (64B: Rx || s)                                 |
+--------------------------------------------------------------------------+
```
$$\text{Total Bytes} = 4 + 1 + 4 + 32 + 64 = 105\text{ bytes}$$
*(Note: 105 bytes is divisible by 3, yielding an exact 140-character Base64 string with zero `=` padding bytes).*

#### ASCII-Armored Signature Block
Both release verification and Git plumbing parse this unified block:
```text
-----BEGIN PIPE-K1 SIGNATURE-----
Version: pipe-k1-v1

<base64-encoded 105-byte binary wire payload>
-----END PIPE-K1 SIGNATURE-----
```
*(Note: In Git commit signing, `pipe-k1-git-shim` accepts and outputs standard `-----BEGIN PGP SIGNATURE-----` wrapping the identical 105-byte base64 payload to ensure native Git porcelain compatibility).*

---

### 2.2 STREAM-ChaCha20-Poly1305 Encryption Framing

#### 2.2.1 Binary Wire Header (Total: 97 Bytes Fixed)
```text
+---------------+---------------+---------------+--------------------+
| Magic (4B)    | Version (1B)  | Mode (1B)     | Ephemeral Pub (32B)|
| "PK01"        | 0x01          | 0x01 or 0x02  | x-only curve point |
+---------------+---------------+---------------+--------------------+
| Recipient Pubkey (32B, x-only)                                     |
+-----------------------------------------------+--------------------+
| Salt (11B, CSPRNG multi-target entropy)                                 |
+-----------------------------------------------+--------------------+
| Header HMAC (16B)                             |
+-----------------------------------------------+
```
* **Byte 0..3 (4B):** Magic ASCII `PK01` (`0x50 0x4B 0x30 0x31`).
* **Byte 4 (1B):** Version `0x01`.
* **Byte 5 (1B):** Mode:
  * `0x01` = **Authenticated Mode** (Sender identity authenticated via signed trailer).
  * `0x02` = **Anonymous Mode** (Zero sender identity; pure forward-secret ephemeral encryption).
* **Byte 6..37 (32B):** Ephemeral Public Key ($E_{pub}$, x-only).
* **Byte 38..69 (32B):** Recipient Public Key ($R_{pub}$, x-only).
* **Byte 70..80 (11B):** Salt (11 bytes CSPRNG entropy).
* **Byte 81..96 (16B):** Header HMAC: First 16 bytes (indices `0..15`) of $\text{HMAC-SHA256}(\text{HeaderKey}, \text{Header}[0..80])$.

#### 2.2.2 Key Schedule & KDF Pipeline

##### Sender Derivation (Encryption):
1. **Entropy Hedging & Ephemeral Key Generation:**
   * Host CSPRNG generates 32 bytes of kernel entropy: $E_{os} \leftarrow \text{getrandom}(32)$.
   * **Optional Physical Entropy Hedging (`--entropy-fd <N>`):** If an external physical entropy source (e.g. dice/coin flips, airgapped hardware TRNG) is supplied via file descriptor $N$, read arbitrary raw entropy bytes $H_{phys}$. Ephemeral private scalar is derived as:
     $$E_{priv} = \text{TaggedHash}(\text{"pipe-k1/v1/entropy"}, E_{os} \parallel H_{phys})$$
     If $E_{priv} = 0$ or $E_{priv} \ge n$, re-hash iteratively: $E_{priv} = \text{TaggedHash}(\text{"pipe-k1/v1/entropy"}, E_{priv})$.
   * If no external entropy is provided, $E_{priv} = E_{os}$.
   * Ephemeral public point: $E_{pub} = \text{point\_x}(E_{priv} \cdot G)$. Note: Since the affine x-coordinate of $k \cdot P$ is identical to $k \cdot (-P)$, scalar parity negation is optional for ECDH shared point calculation, but canonicalizing $E_{priv}$ to even $Y$ parity ($sk' = n - sk$) matches BIP-340 Schnorr conventions.
2. Validate $R_{pub}$ via $\text{lift\_x}(R_{pub})$; abort with exit code `2` if invalid local input.
3. $\text{SharedPoint} = \text{point\_mul}(E_{priv}, \text{lift\_x}(R_{pub}))$. Abort if point is $\mathcal{O}$.
4. $\text{IKM} = \text{SHA-256}(\text{point\_x}(\text{SharedPoint}))$.
5. $\text{RootKey} (32\text{B}) = \text{HKDF-Extract}(\text{salt} = \text{Header.Salt}, \text{IKM} = \text{IKM})$.
6. $\text{HeaderKey} (32\text{B}) = \text{HKDF-Expand}(\text{RootKey}, \text{info} = \text{"pipe-k1/v1/header"}, L = 32)$.
7. $\text{PayloadKey} (32\text{B}) = \text{HKDF-Expand}(\text{RootKey}, \text{info} = \text{"pipe-k1/v1/stream"}, L = 32)$.
8. Compute $\text{HeaderHMAC}[16\text{B}] = \text{HMAC-SHA256}(\text{HeaderKey}, \text{Header}[0..80])[0..15]$.

##### Recipient Derivation & Verification (Decryption):
1. Parse 97-byte header from wire. Check magic `PK01`, version `0x01`, and mode $\in \{0x01, 0x02\}$. If header is malformed, abort with exit code `1`.
2. Validate $E_{pub}$ from wire via $\text{lift\_x}(E_{pub})$; if invalid curve point, abort with exit code `1` (wire corruption / tampering).
3. Assert that $R_{pub}$ in header matches recipient's known public key: $\text{point\_x}(R_{priv} \cdot G) == \text{Header.}R_{pub}$. Abort with exit code `1` if mismatched.
4. $\text{SharedPoint} = \text{point\_mul}(R_{priv}, \text{lift\_x}(E_{pub}))$. Abort with exit code `1` if point is $\mathcal{O}$.
5. $\text{IKM} = \text{SHA-256}(\text{point\_x}(\text{SharedPoint}))$.
6. $\text{RootKey} (32\text{B}) = \text{HKDF-Extract}(\text{salt} = \text{Header.Salt}, \text{IKM} = \text{IKM})$.
7. $\text{HeaderKey} (32\text{B}) = \text{HKDF-Expand}(\text{RootKey}, \text{info} = \text{"pipe-k1/v1/header"}, L = 32)$.
8. $\text{PayloadKey} (32\text{B}) = \text{HKDF-Expand}(\text{RootKey}, \text{info} = \text{"pipe-k1/v1/stream"}, L = 32)$.
9. **Mandatory Header HMAC Check:** Compute $\text{ExpectedHMAC} = \text{HMAC-SHA256}(\text{HeaderKey}, \text{Header}[0..80])[0..15]$.
10. Execute constant-time comparison $\text{ExpectedHMAC} == \text{Header}[81..96]$. If verification fails, **abort immediately with exit code `1`** before processing any stream chunks.


#### 2.2.3 Payload Chunk Framing & Explicit Wire Terminal Tag
Plaintext is processed in chunks up to $65,536\text{ bytes}$ ($64\text{ KiB}$).
Each chunk on the wire consists of:
```text
+-------------------+-----------------+-----------------------+-----------------+
| Length L (4B, BE) | TermTag (1B)    | Ciphertext (L bytes)  | Poly1305 (16B)  |
+-------------------+-----------------+-----------------------+-----------------+
```
$$\text{Total Chunk Wire Size} = 4 + 1 + L + 16 = L + 21\text{ bytes}$$

* **Explicit Wire Terminal Tag Field (`TermTag`, 1 Byte):**
  * Placed directly on the wire at Byte offset 4 of each chunk.
  * `0x00` = Intermediate chunk.
  * `0x01` = Terminal chunk.
  * **Canonical Intermediate Chunk Constraint:** For all intermediate chunks (`TermTag == 0x00`), $L$ **must equal exactly $65,536$**. If $\text{TermTag} == 0x00$ and $L \ne 65,536$, the decryptor aborts immediately with exit code `1` (wire framing violation). Only the terminal chunk (`TermTag == 0x01`) is permitted to have $0 \le L \le 65,536$.
* **Strict Buffer Invariant & Allocation Guard:** 
  The decryptor allocates a single, static resident buffer of $65,536 + 21 = 65,557\text{ bytes}$.
  When parsing a chunk header, if $L > 65,536$ or `TermTag` $\notin \{0x00, 0x01\}$, the reader **aborts immediately** with exit code `1` without performing dynamic memory allocation.
* **Streaming Encryptor 1-Chunk Lookahead Buffer:**
  On non-seekable streams (`stdin` pipe), the encryptor maintains a 1-chunk ($64\text{ KiB}$) lookahead buffer. A full $64\text{ KiB}$ buffer is not emitted until the encryptor attempts to fill the next buffer:
  * If subsequent bytes are present, the current buffer is emitted with $\text{TermTag} = 0x00$.
  * If EOF is reached, the current buffer is emitted with $\text{TermTag} = 0x01$.
  * If the input stream is 0 bytes, exactly one chunk is emitted with $L = 0$ and $\text{TermTag} = 0x01$.
* **Nonce Structure (12 Bytes):**
  * `Bytes 0..7`: 64-bit big-endian unsigned chunk counter ($0, 1, 2, \dots$).
  * `Bytes 8..10`: Reserved (`0x00 0x00 0x00`).
  * `Byte 11`: Terminal Tag (`TermTag`).
* **Additional Authenticated Data (AAD, Total 51 Bytes):**
  $$\text{AAD} = \text{Magic}[4\text{B}] \parallel \text{Version}[1\text{B}] \parallel \text{Mode}[1\text{B}] \parallel R_{pub}[32\text{B}] \parallel L[4\text{B BE}] \parallel \text{ChunkCounter}[8\text{B BE}] \parallel \text{TermTag}[1\text{B}]$$
* **Mode 1 Authenticated Trailer (Anti-Forgery & Non-Repudiation):**
  * In Mode `0x01`, immediately following the terminal chunk ($\text{TermTag} = 0x01$), the wire format appends a **96-byte authenticated trailer**:
    $$\text{Trailer} = \text{SenderPubkey}[32\text{B}] \parallel \text{BIP340-Signature}[64\text{B}]$$
  * The sender signs the overall stream transcript digest:
    $$\text{AuthDigest} = \text{TaggedHash}(\text{"pipe-k1/v1/auth"}, \text{HeaderHMAC}[16\text{B}] \parallel \text{Streaming-SHA-256}(\text{Plaintext}))$$
  * Because the signature commits directly to the plaintext digest and the header HMAC, the recipient **cannot forge** messages to themselves under $PayloadKey$.
* **Post-Stream EOF Invariant (Universal across Mode 1 and Mode 2):**
  Immediately after validating the 96-byte trailer (Mode 1) or terminal chunk (Mode 2), the decryptor must attempt a 1-byte read from the input stream. If `read()` returns $> 0$ (trailing unauthenticated garbage or concatenated streams), the decryptor must discard all output, cryptographically erase temporary buffers, and abort immediately with **exit code `1`**.

---

## 3. UNIX CLI Pipeline & Subcommands

### Universal Exit Code Specification
Across all `pipek1` subcommands, exit codes adhere strictly to:
* `0` = **Success**: Signature valid, stream authenticated and processed.
* `1` = **Cryptographic / Wire Authentication Failure**: Signature mismatch, AEAD Poly1305 tag verification failure, header HMAC mismatch, trailer forgery, unexpected sender identity, malformed wire header/chunk framing, invalid ephemeral curve point, premature EOF / stream truncation, or unauthenticated trailing bytes.
* `2` = **Local Operational Failure**: Invalid command-line arguments, nonexistent or unreadable local key files, payload exceeding configured `--max-size`, out of memory, or local disk full (`ENOSPC`).

---

### 3.1 Encryption (`pipek1 encrypt`)
```bash
# Mode 2 (Anonymous Ephemeral - Default):
cat file.tar | pipek1 encrypt --recipient "$RECIPIENT_NPUB" > file.tar.pk

# Mode 1 (Authenticated Sender):
cat file.tar | PIPEK1_SEC_KEY="$MY_NSEC" pipek1 encrypt --mode 1 --recipient "$RECIPIENT_NPUB" > file.tar.pk

# Deterministic Derivation via BIP-85:
cat file.tar | pipek1 encrypt --bip85-identity 1 --bip85-index 0 --mnemonic-fd 3 --recipient "$RECIPIENT_NPUB" 3<mnemonic.txt > file.tar.pk
```
* **Flags:**
  * `--recipient <npub|hex>` (Required): Target recipient public key.
  * `--mode <1|2>` (Optional, default `2`): `1` = Authenticated, `2` = Anonymous.
  * `--sec-fd <N>` / `--sec-file <path>`: Source for sender private key (required for Mode 1).
  * `--mnemonic-fd <N>` / `--passphrase-fd <N>`: BIP-39 mnemonic/passphrase source for on-the-fly derivation.
  * `--bip85-identity <N>` / `--bip85-index <N>`: BIP-85 31-bit child derivation parameters.

---

### 3.2 Decryption (`pipek1 decrypt`)
```bash
# Mode 2 (Anonymous Decrypt - Default Spool-and-Verify):
cat file.tar.pk | PIPEK1_SEC_KEY="$MY_NSEC" pipek1 decrypt > file.tar

# Mode 1 (Authenticated Decrypt with Expected Sender Validation - Mandatory --sender):
cat file.tar.pk | PIPEK1_SEC_KEY="$MY_NSEC" pipek1 decrypt --sender "$EXPECTED_SENDER_NPUB" > file.tar

# Mode 1 (Untrusted Sender Ingestion with Explicit Opt-In):
cat file.tar.pk | PIPEK1_SEC_KEY="$MY_NSEC" pipek1 decrypt --allow-untrusted-sender > file.tar

# Piped Streaming Mode (Forfeits post-stream rollback for multi-gigabyte pipes):
cat file.tar.pk | PIPEK1_SEC_KEY="$MY_NSEC" pipek1 decrypt --allow-unverified-stream | tar -xz
```
* **Flags:**
  * `--sec-fd <N>` / `--sec-file <path>`: Recipient private key source.
  * `--sender <npub|hex>`: Enforces that message originated from this exact sender in Mode 1.
    * **Anti-Bypass Invariant:** If `--sender` is provided on the CLI and the wire header indicates Mode `0x02` (Anonymous), `pipek1 decrypt` **aborts immediately** with exit code `1` prior to releasing any plaintext.
  * `--allow-untrusted-sender`: Permits Mode 1 decryption when `--sender` is omitted. When active, `pipek1 decrypt` validates the trailer signature against the embedded `SenderPubkey` and emits an informational warning to `stderr`: `Notice: Decrypted Mode 1 stream authenticated by untrusted sender <npub>`. If neither `--sender` nor `--allow-untrusted-sender` is passed for a Mode 1 stream, `pipek1 decrypt` **aborts with exit code `2`** (configuration failure). In Mode 2, this flag is safely ignored.
  * `--allow-unverified-stream`: Disables default spooling across Mode 1 and Mode 2, streaming authenticated chunks directly to stdout as they arrive. Downstream consumers are warned that on-the-fly streaming cannot rollback already-emitted stdout bytes if trailing garbage, premature EOF, or trailer forgery occurs at stream termination.
  * `--max-size <bytes>`: Optional defense-in-depth size ceiling. If spooled bytes exceed `<bytes>`, decryption aborts immediately with exit code `2` and cryptographically shreds the spool, preventing unbounded disk exhaustion from unauthenticated senders.
  * `--mnemonic-fd <N>` / `--passphrase-fd <N>` / `--bip85-identity <N>` / `--bip85-index <N>`: BIP-85 key resolution.
* **Encrypted Spooling & Universal Zero RUP Enforcement (Mode 1 & Mode 2 Default):**
  * By default, `pipek1 decrypt` enforces strict spool-and-verify across **both Mode 1 and Mode 2**:
    * Buffers plaintext in resident memory up to $16\text{ MiB}$.
    * If payload exceeds $16\text{ MiB}$, excess data is spooled to an anonymous disk file via `open(dir, O_TMPFILE | O_RDWR, 0600)` in `${TMPDIR:-/tmp}` (fallback to `mkstemp()` with immediate `unlink()`). Explicit POSIX permissions `0600` (`S_IRUSR | S_IWUSR`) are enforced.
  * **Spool Framing Specification:** Spooled blocks are framed as:
    $$\text{SpoolBlock} = L[4\text{B BE}] \parallel \text{Ciphertext}[L\text{ bytes}] \parallel \text{Poly1305Tag}[16\text{B}]$$
    Where $0 < L \le 65,536$.
  * **Spool Keystream & AAD Invariant:** Spool blocks are encrypted using `AEAD_CHACHA20_POLY1305` under an ephemeral 256-bit key generated via CSPRNG and retained exclusively in `mlock` RAM.
    * **Nonce (12B):** `Bytes 0..7`: 64-bit big-endian sequential block index counter ($0, 1, 2, \dots$). `Bytes 8..11`: `0x00 0x00 0x00 0x00`.
    * **Spool AAD (12B):** $\text{BlockIndex}[8\text{B BE}] \parallel L[4\text{B BE}]$. This binds block order and block length to prevent disk sector manipulation.
  * **Instant Cryptographic Erasure:** Invalidation of temporary spool files is performed via **instant cryptographic erasure** (zeroizing the ephemeral 256-bit spool key in memory and closing the unlinked descriptor). Disk blocks are not synchronously zero-filled, preventing disk I/O thrashing / DoS attacks.
  * Plaintext is decrypted from the spool and released to `stdout` only after the entire stream is authenticated (trailer signature in Mode 1, terminal chunk in Mode 2) and post-stream EOF verified. If any verification step fails, all memory and temporary descriptors are wiped, zero bytes are emitted to `stdout`, and `pipek1` exits with code `1`.

---

### 3.3 Signing (`pipek1 sign`)
```bash
cat release.tar.gz | PIPEK1_SEC_KEY="$NSEC" pipek1 sign > release.tar.gz.sig
```
* **Flags:**
  * `--raw`: Outputs raw 105-byte binary payload (default is ASCII armored).
  * `--sec-fd <N>` / `--sec-file <path>`: Private key source.
  * `--mnemonic-fd <N>` / `--passphrase-fd <N>` / `--bip85-identity <N>` / `--bip85-index <N>`: BIP-85 key resolution.

---

### 3.4 Verification (`pipek1 verify`)
```bash
# 1. Standard Detached Verification (Zero stdout output; exit 0 or 1):
cat release.tar.gz | pipek1 verify --pub "$NPUB" --sig release.tar.gz.sig

# 2. Pipeline Pass-Through (Emits verified bytes to stdout only after EOF validation):
cat release.tar.gz | pipek1 verify --pass-through --pub "$NPUB" --sig release.tar.gz.sig | tar -xz
```
* **Signer Trust Mandate:**
  * Signature intake auto-detects binary `PKSG` payload or ASCII-armored block.
  * If `--pub <npub|hex>` is provided and does not match the signer key embedded in the signature, `pipek1 verify` aborts immediately with exit code `1`.
  * If `--pub` is omitted in standard mode, `pipek1` reads the `Signer Pubkey` from the 105-byte signature payload and emits an informational notice to `stderr`: `Notice: Verifying against embedded untrusted pubkey <npub>`.
  * **Pass-Through Guard:** When `--pass-through` is active, `--pub <npub|hex>` is **mandatory**. Omitting `--pub` during `--pass-through` causes `pipek1 verify` to abort immediately with exit code `2`, preventing arbitrary untrusted code execution in pipelines.
* **Pass-Through Memory Bound Enforcement & Encrypted Disk Spooling:** 
  Spools to resident RAM up to $16\text{ MiB}$. If larger, spills to anonymous disk storage in `${TMPDIR:-/tmp}` using `open(dir, O_TMPFILE | O_RDWR, 0600)` (or `mkstemp` + immediate `unlink`). Spooled blocks are encrypted and authenticated using the identical sequential `AEAD_CHACHA20_POLY1305` ephemeral RAM-only construction and framing specified in Section 3.2. Output is flushed to `stdout` only if EOF verification passes.

---

## 4. Git Plumbing Contract (`pipek1-git-shim`)

Git invokes external signing binaries directly via `execvp(prog, argv)` without shell expansion. Therefore, Git integration is packaged as a dedicated standalone executable or symlink: `pipek1-git-shim`.

Configuration:
```bash
git config gpg.program "pipek1-git-shim"
git config user.signingkey "npub1..." # or hex pubkey
```

### 4.1 CLI Argument Handling & Compatibility Flags
Git invokes `pipek1-git-shim` with standard OpenPGP flags. Cosmetic or GnuPG-specific flags (`--batch`, `--no-tty`, `--display-charset=*`, `--keyid-format=*`, `--extra-check-level=*`) are accepted and safely ignored.

### 4.2 Commit Signing Protocol (`git commit -S`)
1. Git executes `pipek1-git-shim -bsau <keyid>` (flags may be split or combined; `--status-fd=N` is optional).
2. Reads commit payload from `stdin`.
3. **Key Resolution & Validation:**
   * Resolves private key from `PIPEK1_SEC_KEY`, `--sec-file`, or `~/.config/pipek1/git_key`.
   * Calculates derived public key coordinate $X = \text{point\_x}(sk \cdot G)$.
   * If `<keyid>` is provided, validates that $X$ matches `<keyid>` (whether provided as Bech32 `npub` or hex).
   * **Failure Handling:** If `<keyid>` cannot be resolved or does not match:
     - Emits human-readable diagnostic to `stderr`: `pipek1-git-shim: error: signing key <keyid> does not match configured secret key\n`.
     - Writes status line `[GNUPG:] INV_SGNR 0 <keyid>\n` to `--status-fd=N` (if provided).
     - Exits immediately with code `2`.
4. Computes BIP-340 tagged signature over commit payload using tag `"pipek1/v1/sign"`.
5. If `--status-fd=N` was provided on CLI, writes status line with OpenPGP code `8` (SHA-256) terminated by an ASCII Line Feed (`\n`):
   ```text
   [GNUPG:] SIG_CREATED D 1 8 00 <timestamp> <32-byte-hex-pubkey>\n
   ```
6. Writes ASCII-armored signature block to `stdout`:
   ```text
   -----BEGIN PGP SIGNATURE-----

   <base64-encoded 105-byte pipek1 binary signature payload>
   -----END PGP SIGNATURE-----
   ```
   Exits `0`.

### 4.3 Commit Verification Protocol (`git log --show-signature`)
1. Git executes: `pipek1-git-shim --status-fd=N --keyid-format=long --verify <sig_path> <data_path>`.
2. Reads signature from `<sig_path>`. If `<data_path>` is `-`, reads data from `stdin`; otherwise reads file at `<data_path>`.
3. **Signature Parsing & Malformed Packet Fallback:**
   * Unpacks the 105-byte payload, extracting `Timestamp`, `Signer Pubkey`, and the 64-byte Schnorr signature.
   * If parsing fails (e.g., corrupt base64, truncated signature, or foreign non-pipek1 packet):
     - If `--status-fd=N` is provided, writes fallback error lines (terminated by `\n`):
       ```text
       [GNUPG:] NEWSIG\n
       [GNUPG:] ERRSIG 0000000000000000 1 8 00 0000000000 9\n
       ```
     - Emits diagnostic to `stderr`: `pipek1-git-shim: error: malformed or unrecognized signature format\n`.
     - Exits immediately with code `1`.
4. Computes `MessageDigest = SHA-256(TagHash || TagHash || Timestamp || SHA-256(CommitData))`.
5. **Strict Repository Trust Resolution Protocol:**
   * **Trust Hierarchy:**
     1. User-configured repository trust file (`git config pipek1.allowedSignersFile`). Note: OpenSSH-formatted files (`gpg.ssh.allowedSignersFile`) are intentionally not consulted due to token grammar incompatibility.
     2. Local repository metadata file: `$GIT_DIR/pipek1_signers` (or `.git/pipek1_signers`).
        - *Worktree & Submodule Handling:* If `.git` is a regular file, read the `gitdir: <path>` pointer. If `<path>` is relative, resolve it relative to the parent directory of `.git`.
        - *Common Directory Dereferencing:* In linked worktrees, check `<resolved_path>/commondir`. If present, read the relative common path and also inspect `<commondir_resolved_path>/pipek1_signers` to inherit repository-wide signers.
        - Traversal ascends parent directories until a `.git` root or filesystem boundary is reached; it never escapes the repository boundary.
     3. User-global trust database: `~/.config/pipek1/allowed_signers`.
   * **Security Rule on Working Tree Files:** Tracked working tree files (e.g. `./.pipek1_signers`) are **never auto-loaded by default**, preventing malicious PR branches from hijacking identity verification. Working tree files are only consulted if explicitly permitted via `git config pipek1.allowInTreeSigners true`.
   * **Robust Whitespace Parsing & Bare Key Support:** Each line follows `[<identity>] <npub_or_hex_pubkey>`.
     - The parser extracts the **final whitespace-delimited token on the line** as the public key.
     - All preceding tokens are joined as `<identity>`.
     - **Bare Key Fallback:** If a line contains only a public key without an identity, `<identity>` defaults to `<npub>`, preventing empty string tokens in porcelain output. Lines beginning with `#` and empty lines are ignored.
6. Formats `<date-string>` as ISO `YYYY-MM-DD` from the extracted UTC timestamp.
7. **Status-FD Protocol Serialization:**
   Writes to file descriptor `N` matching Git's exact parser requirements (all lines terminated by `\n`):
   * **Valid Signature & Trusted Identity:**
     ```text
     [GNUPG:] NEWSIG\n
     [GNUPG:] GOODSIG <hex-pubkey> <identity>\n
     [GNUPG:] VALIDSIG <hex-pubkey> <YYYY-MM-DD> <timestamp> 0 4 0 1 8 00 <hex-pubkey>\n
     [GNUPG:] TRUST_ULTIMATE 0 pgp\n
     ```
     Exits `0`.
   * **Valid Signature & Untrusted Identity:**
     ```text
     [GNUPG:] NEWSIG\n
     [GNUPG:] GOODSIG <hex-pubkey> <npub>\n
     [GNUPG:] VALIDSIG <hex-pubkey> <YYYY-MM-DD> <timestamp> 0 4 0 1 8 00 <hex-pubkey>\n
     [GNUPG:] TRUST_UNDEFINED 0 pgp\n
     ```
     Exits `0` (signature is valid; Git porcelain warns of untrusted key).
   * **Tampered / Invalid Signature:**
     ```text
     [GNUPG:] NEWSIG\n
     [GNUPG:] BADSIG <hex-pubkey> <identity_or_npub>\n
     ```
     *(If identity cannot be resolved from `allowed_signers` or was empty, falls back to `<npub>`)*.  
     Exits `1`.

---

## 5. Security & Threat Invariant Matrix

| Threat Vector | Defense Mechanism | Mathematical / Systems Invariant |
| :--- | :--- | :--- |
| **Odd $Y$ Schnorr Failure** | BIP-340 Parity Negation | Asserts $sk' = n - sk$ if $Y$ coordinate of $sk \cdot G$ is odd. |
| **Invalid Curve Injection** | Strict $\text{lift\_x}$ validation | Rejects $X \ge p$ and non-quadratic residues before scalar multiplication; exits `1` on wire. |
| **Affine Domain Errors** | Strict $\text{point\_x}$ usage | Never passes curve points into $\text{lift\_x}$; extracts coordinates via $\text{point\_x}(P)$. |
| **Process Table Snooping** | Banning CLI argv keys | Positional `--sec` flags rejected with fatal error; env/FD only. |
| **Environment Scraping** | Comprehensive Memory Scrubbing | Zeroes `PIPEK1_SEC_KEY` and `PIPEK1_MNEMONIC` in `environ`; disables core dumps via `PR_SET_DUMPABLE`. |
| **Descriptor Bleed** | `FD_CLOEXEC` + Immediate Close | Descriptors and files closed immediately upon ingestion to prevent child leak. |
| **Cross-Protocol Replay** | BIP-340 Tagged Hashes | `Tag = "pipek1/v1/sign"` isolates sigs from Nostr events & Taproot. |
| **Stream Chunk Truncation** | Explicit Wire `TermTag` & Exit 1 | Premature EOF before `0x01` chunk or trailer triggers exit code `1`. |
| **Trailing Garbage Injection**| Post-Stream EOF Check | Mandatory 1-byte read after trailer/terminal chunk; non-zero read triggers exit code `1`. |
| **Chunk Stuffing / CPU Exhaust**| Canonical Intermediate $L$ | Intermediate chunks (`TermTag=0x00`) must have $L=65,536$; else abort with exit `1`. |
| **Header Tampering / Swapping** | Mandatory Header HMAC Check | Decryptor validates $\text{HMAC-SHA256}(\text{HeaderKey}, \text{Header}[0..80])[0..15]$ before chunks; exit `1` on failure. |
| **Length Bomb Buffer Overflow**| Preallocated Static Buffer | Rejects $L > 65,536$ immediately with exit code `1` without memory allocation. |
| **Mode 1 Recipient Forgery**| Authenticated Trailer | Trailer signs $\text{TaggedHash}(\text{Tag}, \text{HeaderHMAC} \parallel \text{PlaintextDigest})$ where $\text{Tag} = \text{pipek1/v1/auth}$. |
| **Mode 1 Untrusted Ingestion**| Mandatory `--sender` / Opt-In | Mode 1 rejects omitted `--sender` with exit `2` unless `--allow-untrusted-sender` is passed. |
| **Universal RUP Bypass** | Spool-and-Verify Default | Mode 1 and Mode 2 buffer $\le 16\text{ MiB}$ RAM + `O_TMPFILE` before emitting to stdout. |
| **Blind Spool Disk Exhaustion**| Configurable `--max-size` | Aborts with exit `2` and shreds spool if size ceiling exceeded prior to trailer verification. |
| **Disk Keystream / Block Snooping**| Sequential Spool AEAD Framing | Spooled blocks have explicit $L[4\text{B}]$, sequential 64-bit nonce counter, and AAD ($BlockIndex \parallel L$). |
| **Spool Permissions Vulnerability**| POSIX `0600` Mode Argument | `open(..., O_TMPFILE | O_RDWR, 0600)` prevents world/group read access on spilled chunks. |
| **Spool Cleanup Disk Thrashing**| Cryptographic Erasure | Spool invalidated instantly by zeroing RAM key and closing unlinked descriptor; no disk zero-fill. |
| **Git In-Tree Trust Hijacking**| Untrusted Tree Shield | Tracked in-tree `.pipek1_signers` ignored by default; trust anchored in config or `$GIT_DIR`. |
| **Git Linked Worktree Isolation**| `commondir` Traversal | Resolves `commondir` pointer in linked worktrees to inherit main repository trust anchors. |
| **Git Invocation Syntax Mismatch**| Dedicated `pipek1-git-shim` | Avoids shell string parsing failures in native Git `execvp()` execution model. |
| **Git Status Parser Deadlock**| Strict `\n` Line Framing | Every status-FD line explicitly terminated with `\n` (`0x0A`). |
| **Bare Key Trustfile Display Bug**| Npub Identity Fallback | Emits `<npub>` when trust entry identity is empty, preventing `Good signature from ""` bug. |
| **Git Foreign Sig Porcelain Crash**| ERRSIG Fallback Protocol | Emits standard `ERRSIG` on status-FD for non-pipek1/malformed packets; exits `1`. |
| **Compromised Hardware TRNG** | Hybrid Entropy Hedging (`--entropy-fd`)| Mixes $E_{os} \parallel H_{phys}$ via $\text{TaggedHash}(\text{"pipek1/v1/entropy"}, \cdot)$; signing uses deterministic RFC 6979/BIP-340. |
| **Memory Scrape Post-Exit** | `mlock` + `ZeroizeOnDrop` | Secret keys and intermediate scalars wiped from physical RAM. |
