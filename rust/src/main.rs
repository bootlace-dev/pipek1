// SPDX-License-Identifier: MIT
// Copyright (c) 2026 bootlace-dev

//! pipek1: Pure Stateless UNIX Cryptographic Filter (Specification v1.9)
//! Anonymous / Zero-PII Invariant: bootlace-dev <bootlace-dev@users.noreply.github.com>

use base64::Engine as _;
use bech32::{Bech32, Hrp};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Tag};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use k256::{AffinePoint, PublicKey};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use std::env;
use std::fs;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use pipek1::Pipek1Error;
mod spool;
use spool::StreamSpooler;

type HmacSha512 = Hmac<Sha512>;

pub const MAGIC_HEADER: &[u8; 4] = b"PK01";
pub const MAGIC_SIGNATURE: &[u8; 4] = b"PKSG";
pub const WIRE_HEADER_SIZE: usize = 97;
pub const CHUNK_HEADER_SIZE: usize = 5;
pub const SIGNATURE_PAYLOAD_SIZE: usize = 105;
pub const CHUNK_SIZE: usize = 65536; // 64 KiB
pub const TAG_SIZE: usize = 16;      // Poly1305 16 bytes
pub const TRAILER_SIZE: usize = 96;  // SenderPubkey (32B) + Signature (64B)

pub const TAG_SIGN: &str = "pipek1/v1/sign";
pub const TAG_AUTH: &str = "pipek1/v1/auth";
pub const TAG_ENTROPY: &str = "pipek1/v1/entropy";
pub const INFO_HEADER: &[u8] = b"pipek1/v1/header";
pub const INFO_STREAM: &[u8] = b"pipek1/v1/stream";

type HmacSha256 = Hmac<Sha256>;

/// Computes BIP-340 Tagged Hash: SHA-256(SHA-256(tag) || SHA-256(tag) || msg)
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(msg);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Decodes an input string (nsec/npub Bech32 or 32-byte hex) into a 32-byte array
pub fn parse_key_bytes(input: &str) -> Result<[u8; 32], String> {
    let trimmed = input.trim();
    if trimmed.starts_with("nsec1") || trimmed.starts_with("npub1") {
        let (_hrp, data) = bech32::decode(trimmed).map_err(|e| format!("Bech32 error: {}", e))?;
        if data.len() != 32 {
            return Err(format!("Expected 32 bytes in Bech32 data, got {}", data.len()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&data);
        Ok(out)
    } else {
        let hex_bytes = hex::decode(trimmed).map_err(|e| format!("Hex decode error: {}", e))?;
        if hex_bytes.len() != 32 {
            return Err(format!("Expected 32 bytes of hex, got {}", hex_bytes.len()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hex_bytes);
        Ok(out)
    }
}

#[derive(Default, Clone, Debug)]
pub struct KeyIntakeArgs {
    pub sec_fd: Option<i32>,
    pub sec_file: Option<String>,
    pub mnemonic_fd: Option<i32>,
    pub passphrase_fd: Option<i32>,
    pub bip85_identity: Option<u32>,
    pub bip85_index: Option<u32>,
}

#[cfg(unix)]
fn set_cloexec(fd: i32) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}

/// Memory Scrubbing Helper for process environment (/proc/$PID/environ)
pub fn scrub_env_var(key: &str) {
    #[cfg(target_os = "linux")]
    unsafe {
        extern "C" {
            static mut environ: *mut *mut libc::c_char;
        }
        if !environ.is_null() {
            let mut ep = environ;
            let prefix = format!("{}=", key);
            while !(*ep).is_null() {
                let entry = std::ffi::CStr::from_ptr(*ep);
                if let Ok(s) = entry.to_str() {
                    if s.starts_with(&prefix) {
                        let len = s.len();
                        std::ptr::write_bytes(*ep as *mut u8, 0, len);
                        break;
                    }
                }
                ep = ep.add(1);
            }
        }
    }
    env::remove_var(key);
}

pub fn scrub_all_sensitive_env() {
    scrub_env_var("PIPEK1_SEC_KEY");
    scrub_env_var("PIPEK1_MNEMONIC");
    scrub_env_var("PIPEK1_PASSPHRASE");
}

/// Computes BIP-85 Application 128002' operational secp256k1 child key from BIP-39 mnemonic
pub fn derive_bip85_operational_key(
    mnemonic_str: &str,
    passphrase_str: &str,
    identity: u32,
    index: u32,
) -> Result<[u8; 32], Pipek1Error> {
    use bip32::{DerivationPath, XPrv};
    use bip39::Mnemonic;
    use std::str::FromStr;

    let mnemonic = Mnemonic::from_str(mnemonic_str.trim())
        .map_err(|e| Pipek1Error::UsageError(format!("Invalid BIP-39 mnemonic: {}", e)))?;
    let mut seed = mnemonic.to_seed(passphrase_str.trim());

    let root_xprv = XPrv::new(&seed)
        .map_err(|e| Pipek1Error::UsageError(format!("BIP-32 root key derivation failed: {}", e)))?;
    seed.zeroize();

    // BIP-85 path: m/83696968'/128002'/<identity>'/<index>'
    let path_str = format!("m/83696968'/128002'/{}'/{}'", identity, index);
    let path = DerivationPath::from_str(&path_str)
        .map_err(|e| Pipek1Error::UsageError(format!("Invalid BIP-85 derivation path '{}': {}", path_str, e)))?;

    let mut current_xprv = root_xprv;
    for child_num in path {
        current_xprv = current_xprv.derive_child(child_num)
            .map_err(|e| Pipek1Error::UsageError(format!("BIP-85 child derivation failed: {}", e)))?;
    }

    // Extract child private scalar (32 bytes)
    let mut child_priv = current_xprv.private_key().to_bytes();

    // BIP-85 HMAC-SHA512 extraction: Key="bip-entropy-from-k", Data=child_priv
    let mut mac = <HmacSha512 as Mac>::new_from_slice(b"bip-entropy-from-k")
        .expect("HMAC can take key of any size");
    mac.update(&child_priv);
    let mut hmac_res = mac.finalize().into_bytes();
    child_priv.zeroize();

    // First 32 bytes (256 MSB)
    let mut operational_sk = [0u8; 32];
    operational_sk.copy_from_slice(&hmac_res[0..32]);
    hmac_res.zeroize();

    // Verify valid non-zero scalar modulo curve order
    if operational_sk == [0u8; 32] {
        return Err(Pipek1Error::UsageError("Derived BIP-85 scalar is zero".into()));
    }
    // Attempt parsing as secp256k1 SigningKey to validate boundary
    SigningKey::from_bytes(&operational_sk)
        .map_err(|e| Pipek1Error::UsageError(format!("Derived BIP-85 scalar invalid on secp256k1: {}", e)))?;

    Ok(operational_sk)
}

/// Resolves secret key from CLI flags (--sec-fd, --sec-file, BIP-85 flags), PIPEK1_SEC_KEY env, or git_key file
pub fn load_secret_key(args: &KeyIntakeArgs) -> Result<[u8; 32], Pipek1Error> {
    #[cfg(target_os = "linux")]
    unsafe {
        // Disable core dumps and ptrace inspection
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

    // Eagerly grab env vars, then scrub environ immediately
    let mut env_mnemonic = env::var("PIPEK1_MNEMONIC").ok();
    let mut env_passphrase = env::var("PIPEK1_PASSPHRASE").ok();
    let mut env_sec_key = env::var("PIPEK1_SEC_KEY").ok();
    scrub_all_sensitive_env();

    if let Some(fd_num) = args.sec_fd {
        #[cfg(unix)]
        {
            use std::os::unix::io::FromRawFd;
            set_cloexec(fd_num);
            let mut f = unsafe { fs::File::from_raw_fd(fd_num) };
            let mut s = String::new();
            f.read_to_string(&mut s).map_err(|e| Pipek1Error::UsageError(format!("Failed to read --sec-fd: {}", e)))?;
            drop(f); // explicitly close fd immediately
            let k = parse_key_bytes(&s).map_err(Pipek1Error::UsageError)?;
            s.zeroize();
            return Ok(k);
        }
    }

    if let Some(ref path) = args.sec_file {
        let mut s = fs::read_to_string(path).map_err(|e| Pipek1Error::UsageError(format!("Failed to read --sec-file: {}", e)))?;
        let k = parse_key_bytes(&s).map_err(Pipek1Error::UsageError)?;
        s.zeroize();
        return Ok(k);
    }

    // BIP-85 derivation pathway
    let mnemonic_input = if let Some(m_fd) = args.mnemonic_fd {
        #[cfg(unix)]
        {
            use std::os::unix::io::FromRawFd;
            set_cloexec(m_fd);
            let mut f = unsafe { fs::File::from_raw_fd(m_fd) };
            let mut s = String::new();
            f.read_to_string(&mut s).map_err(|e| Pipek1Error::UsageError(format!("Failed to read --mnemonic-fd: {}", e)))?;
            drop(f);
            Some(s)
        }
        #[cfg(not(unix))]
        None
    } else {
        env_mnemonic.take()
    };

    if let Some(mut m_str) = mnemonic_input {
        let mut passphrase_str = if let Some(p_fd) = args.passphrase_fd {
            #[cfg(unix)]
            {
                use std::os::unix::io::FromRawFd;
                set_cloexec(p_fd);
                let mut f = unsafe { fs::File::from_raw_fd(p_fd) };
                let mut s = String::new();
                f.read_to_string(&mut s).map_err(|e| Pipek1Error::UsageError(format!("Failed to read --passphrase-fd: {}", e)))?;
                drop(f);
                s
            }
            #[cfg(not(unix))]
            String::new()
        } else {
            env_passphrase.take().unwrap_or_default()
        };

        let identity = args.bip85_identity.unwrap_or(0);
        let index = args.bip85_index.unwrap_or(0);
        let res = derive_bip85_operational_key(&m_str, &passphrase_str, identity, index);
        m_str.zeroize();
        passphrase_str.zeroize();
        return res;
    }

    if let Some(mut val) = env_sec_key.take() {
        let res = parse_key_bytes(&val);
        val.zeroize();
        let k = res.map_err(Pipek1Error::UsageError)?;
        return Ok(k);
    }

    // Git fallback key check: ~/.config/pipek1/git_key
    if let Ok(home) = env::var("HOME") {
        let git_key_path = PathBuf::from(home).join(".config/pipek1/git_key");
        if git_key_path.is_file() {
            if let Ok(mut s) = fs::read_to_string(&git_key_path) {
                let res = parse_key_bytes(&s);
                s.zeroize();
                if let Ok(k) = res {
                    return Ok(k);
                }
            }
        }
    }

    Err(Pipek1Error::UsageError("No secret key provided: set PIPEK1_SEC_KEY, pass --sec-fd / --sec-file, or supply --mnemonic-fd / PIPEK1_MNEMONIC for BIP-85".into()))
}

/// Formats a 32-byte public key as Bech32 npub
pub fn encode_npub(pk_x: &[u8]) -> String {
    let hrp = Hrp::parse("npub").unwrap();
    bech32::encode::<Bech32>(hrp, pk_x).unwrap()
}

/// Generates BIP-340 Schnorr signature over message digest with timestamp
pub fn sign_stream_payload(signing_key: &SigningKey, msg_digest: &[u8; 32], timestamp: u32) -> [u8; SIGNATURE_PAYLOAD_SIZE] {
    let mut ts_and_digest = [0u8; 36];
    ts_and_digest[0..4].copy_from_slice(&timestamp.to_be_bytes());
    ts_and_digest[4..36].copy_from_slice(msg_digest);

    let m_hash = tagged_hash(TAG_SIGN, &ts_and_digest);
    let signature = signing_key.sign_raw(&m_hash, &[0u8; 32]).expect("signing failed");

    let mut payload = [0u8; SIGNATURE_PAYLOAD_SIZE];
    payload[0..4].copy_from_slice(MAGIC_SIGNATURE);
    payload[4] = 0x01; // Version
    payload[5..9].copy_from_slice(&timestamp.to_be_bytes());
    
    let pk_x = signing_key.verifying_key().to_bytes();
    payload[9..41].copy_from_slice(pk_x.as_slice());
    payload[41..105].copy_from_slice(&signature.to_bytes());
    payload
}

/// Verifies a BIP-340 Schnorr signature payload against a message digest
pub fn verify_stream_payload(payload: &[u8; SIGNATURE_PAYLOAD_SIZE], msg_digest: &[u8; 32]) -> Result<[u8; 32], String> {
    if &payload[0..4] != MAGIC_SIGNATURE {
        return Err("Invalid magic bytes in signature payload".to_string());
    }
    if payload[4] != 0x01 {
        return Err("Unsupported signature version".to_string());
    }
    let timestamp = u32::from_be_bytes(payload[5..9].try_into().unwrap());
    let mut ts_and_digest = [0u8; 36];
    ts_and_digest[0..4].copy_from_slice(&timestamp.to_be_bytes());
    ts_and_digest[4..36].copy_from_slice(msg_digest);

    let m_hash = tagged_hash(TAG_SIGN, &ts_and_digest);
    let pk_x = &payload[9..41];
    let sig_bytes = &payload[41..105];

    let vk = VerifyingKey::from_bytes(pk_x).map_err(|e| format!("Invalid public key: {}", e))?;
    let sig = Signature::try_from(sig_bytes).map_err(|e| format!("Invalid signature format: {}", e))?;

    vk.verify_raw(&m_hash, &sig).map_err(|e| format!("Schnorr verification failed: {}", e))?;

    let mut out_pk = [0u8; 32];
    out_pk.copy_from_slice(pk_x);
    Ok(out_pk)
}

/// Builds 12-byte STREAM nonce: [ChunkCounter (8B BE)] || [0x00 0x00 0x00] || [TermTag (1B)]
pub fn build_nonce(counter: u64, term_tag: u8) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&counter.to_be_bytes());
    nonce[8..11].copy_from_slice(&[0x00, 0x00, 0x00]);
    nonce[11] = term_tag;
    nonce
}

/// Builds 51-byte Additional Authenticated Data (AAD) for STREAM chunk
pub fn build_aad(magic: &[u8; 4], version: u8, mode: u8, recip_pub: &[u8; 32], chunk_len: u32, counter: u64, term_tag: u8) -> [u8; 51] {
    let mut aad = [0u8; 51];
    aad[0..4].copy_from_slice(magic);
    aad[4] = version;
    aad[5] = mode;
    aad[6..38].copy_from_slice(recip_pub);
    aad[38..42].copy_from_slice(&chunk_len.to_be_bytes());
    aad[42..50].copy_from_slice(&counter.to_be_bytes());
    aad[50] = term_tag;
    aad
}

/// Derives Key Schedule: IKM -> HKDF -> (HeaderKey, PayloadKey)
pub fn derive_keys(ikm: &[u8; 32], salt: &[u8; 11]) -> Result<([u8; 32], [u8; 32]), String> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut header_key = [0u8; 32];
    let mut payload_key = [0u8; 32];
    hk.expand(INFO_HEADER, &mut header_key).map_err(|e| format!("HKDF header expand failed: {}", e))?;
    hk.expand(INFO_STREAM, &mut payload_key).map_err(|e| format!("HKDF stream expand failed: {}", e))?;
    Ok((header_key, payload_key))
}

/// Computes Header HMAC over first 81 bytes (magic through salt)
pub fn compute_header_hmac(header_key: &[u8; 32], header_81: &[u8]) -> [u8; 16] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(header_key).expect("HMAC can take key of any size");
    mac.update(header_81);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[0..16]);
    out
}

/// Lifts an x-only public key to AffinePoint (even Y parity per BIP-340)
pub fn lift_x(x_bytes: &[u8; 32]) -> Result<AffinePoint, String> {
    let mut sec1 = [0u8; 33];
    sec1[0] = 0x02; // Even Y
    sec1[1..33].copy_from_slice(x_bytes);
    let pk = PublicKey::from_sec1_bytes(&sec1).map_err(|e| format!("Invalid curve point: {}", e))?;
    Ok(pk.to_projective().to_affine())
}

/// Computes secp256k1 shared point: scalar * point
pub fn ecdh_shared_x(priv_scalar: &[u8; 32], pub_x: &[u8; 32]) -> Result<[u8; 32], String> {
    let sk = k256::NonZeroScalar::try_from(priv_scalar.as_slice()).map_err(|e| format!("Invalid private scalar: {}", e))?;
    let pt = lift_x(pub_x)?;
    let shared = pt * sk.as_ref();
    let aff = shared.to_affine();
    if aff.is_identity().into() {
        return Err("Point at infinity".to_string());
    }
    let enc = aff.to_encoded_point(false);
    let x = enc.x().ok_or("Missing x coordinate")?;
    let mut out = [0u8; 32];
    out.copy_from_slice(x);
    Ok(Sha256::digest(out).into())
}

/// Streaming Encryptor Implementation
pub fn run_encrypt(recipient_hex: &str, mode: u8, key_args: &KeyIntakeArgs, entropy_fd: Option<i32>) -> Result<(), Pipek1Error> {
    let recip_x = parse_key_bytes(recipient_hex).map_err(Pipek1Error::UsageError)?;
    
    // 1. Generate ephemeral keypair (E_priv, E_pub)
    // Hybrid Entropy Hedging: OsRng (32B) + optional Physical Entropy (via FD)
    let mut os_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut os_entropy);

    let eph_priv_bytes = if let Some(fd_num) = entropy_fd {
        #[cfg(unix)]
        {
            use std::os::unix::io::FromRawFd;
            set_cloexec(fd_num);
            let mut f = unsafe { fs::File::from_raw_fd(fd_num) };
            let mut physical_entropy = Vec::new();
            (&mut f).take(CHUNK_SIZE as u64).read_to_end(&mut physical_entropy)
                .map_err(|e| Pipek1Error::UsageError(format!("Failed to read entropy fd: {}", e)))?;
            drop(f); // explicitly close FD immediately

            if physical_entropy.is_empty() {
                return Err(Pipek1Error::UsageError("Entropy file descriptor was empty".into()));
            }

            // TaggedHash("pipek1/v1/entropy", OsRng || PhysicalEntropy)
            let mut hedge_input = Vec::with_capacity(32 + physical_entropy.len());
            hedge_input.extend_from_slice(&os_entropy);
            hedge_input.extend_from_slice(&physical_entropy);
            let mut mixed = tagged_hash(TAG_ENTROPY, &hedge_input);

            // Re-hash if scalar is zero or >= curve order
            while SigningKey::from_bytes(&mixed).is_err() || mixed == [0u8; 32] {
                mixed = tagged_hash(TAG_ENTROPY, &mixed);
            }
            mixed
        }
        #[cfg(not(unix))]
        {
            os_entropy
        }
    } else {
        os_entropy
    };

    let signing_key = SigningKey::from_bytes(&eph_priv_bytes)
        .map_err(|e| Pipek1Error::UsageError(format!("Invalid ephemeral secret scalar: {}", e)))?;
    let eph_pub_x: [u8; 32] = signing_key.verifying_key().to_bytes().into();

    // 2. Generate 11-byte random salt
    let mut salt = [0u8; 11];
    OsRng.fill_bytes(&mut salt);

    // 3. Mode 1 Eager Key Intake: Ingest and validate sender key before emitting any wire bytes
    let sender_signing_key = if mode == 0x01 {
        let sender_priv = load_secret_key(key_args)
            .map_err(|e| Pipek1Error::UsageError(format!("Mode 1 requires sender secret key: {}", e)))?;
        Some(SigningKey::from_bytes(&sender_priv)
            .map_err(|e| Pipek1Error::UsageError(format!("Invalid sender secret scalar: {}", e)))?)
    } else {
        None
    };

    // 4. Compute ECDH IKM and derive keys
    let ikm = ecdh_shared_x(&eph_priv_bytes, &recip_x)
        .map_err(|e| Pipek1Error::UsageError(format!("ECDH calculation failed: {}", e)))?;
    let (header_key, payload_key) = derive_keys(&ikm, &salt)
        .map_err(|e| Pipek1Error::UsageError(format!("Key derivation failed: {}", e)))?;

    // 5. Assemble 97-byte header
    let mut header = [0u8; WIRE_HEADER_SIZE];
    header[0..4].copy_from_slice(MAGIC_HEADER);
    header[4] = 0x01; // Version
    header[5] = mode;
    header[6..38].copy_from_slice(&eph_pub_x);
    header[38..70].copy_from_slice(&recip_x);
    header[70..81].copy_from_slice(&salt);

    let hmac_16 = compute_header_hmac(&header_key, &header[0..81]);
    header[81..97].copy_from_slice(&hmac_16);

    let mut stdout = io::stdout();
    stdout.write_all(&header)?;

    // 6. Stream encryption loop (Full 64 KiB chunk accumulator with 1-chunk lookahead)
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&payload_key));
    let mut stdin = io::stdin();
    let mut chunk_counter: u64 = 0;

    fn fill_buffer<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
        let mut total = 0;
        while total < buf.len() {
            match reader.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(total)
    }

    let mut cur_buf = vec![0u8; CHUNK_SIZE];
    let mut next_buf = vec![0u8; CHUNK_SIZE];

    let mut cur_len = fill_buffer(&mut stdin, &mut cur_buf)?;
    let mut plaintext_hasher = Sha256::new();

    loop {
        let next_len = fill_buffer(&mut stdin, &mut next_buf)?;
        let term_tag = if next_len == 0 { 0x01u8 } else { 0x00u8 };

        let chunk_len = cur_len as u32;
        let nonce_bytes = build_nonce(chunk_counter, term_tag);
        let aad = build_aad(MAGIC_HEADER, 0x01, mode, &recip_x, chunk_len, chunk_counter, term_tag);

        let mut chunk_header = [0u8; CHUNK_HEADER_SIZE];
        chunk_header[0..4].copy_from_slice(&chunk_len.to_be_bytes());
        chunk_header[4] = term_tag;
        stdout.write_all(&chunk_header)?;

        if mode == 0x01 {
            plaintext_hasher.update(&cur_buf[0..cur_len]);
        }

        let mut block = cur_buf[0..cur_len].to_vec();
        let tag = cipher.encrypt_in_place_detached(&nonce_bytes.into(), &aad, &mut block)
            .map_err(|e| Pipek1Error::UsageError(format!("Chunk encryption failed: {}", e)))?;

        stdout.write_all(&block)?;
        stdout.write_all(tag.as_slice())?;

        chunk_counter = chunk_counter.checked_add(1).ok_or_else(|| Pipek1Error::UsageError("Chunk counter overflow".into()))?;

        if next_len == 0 {
            break;
        }

        std::mem::swap(&mut cur_buf, &mut next_buf);
        cur_len = next_len;
    }

    // 7. Mode 1 Authenticated Trailer (96 bytes: SenderPubkey [32B] || BIP340-Signature [64B])
    if let Some(signing_key) = sender_signing_key {
        let sender_pub: [u8; 32] = signing_key.verifying_key().to_bytes().into();

        let pt_digest = plaintext_hasher.finalize();
        let mut auth_transcript = [0u8; 48];
        auth_transcript[0..16].copy_from_slice(&hmac_16);
        auth_transcript[16..48].copy_from_slice(&pt_digest);

        let auth_hash = tagged_hash(TAG_AUTH, &auth_transcript);
        let sig = signing_key.sign_raw(&auth_hash, &[0u8; 32])
            .map_err(|e| Pipek1Error::UsageError(format!("Trailer signing failed: {}", e)))?;

        stdout.write_all(&sender_pub)?;
        stdout.write_all(&sig.to_bytes())?;
    }

    stdout.flush()?;
    Ok(())
}

/// Streaming Decryptor Implementation (Spool-and-Verify with Zero RUP Invariant)
pub fn run_decrypt(expected_sender: Option<String>, allow_untrusted_sender: bool, allow_unverified_stream: bool, max_size: Option<u64>, key_args: &KeyIntakeArgs) -> Result<(), Pipek1Error> {
    let recip_priv = load_secret_key(key_args)?;
    let signing_key = SigningKey::from_bytes(&recip_priv)
        .map_err(|e| Pipek1Error::UsageError(format!("Invalid secret key: {}", e)))?;
    let expected_recip_pub: [u8; 32] = signing_key.verifying_key().to_bytes().into();

    let mut stdin = io::stdin();

    // 1. Read and parse 97-byte wire header
    let mut header = [0u8; WIRE_HEADER_SIZE];
    stdin.read_exact(&mut header).map_err(|e| Pipek1Error::WireCorruption(format!("Failed to read 97-byte header: {}", e)))?;

    if &header[0..4] != MAGIC_HEADER {
        return Err(Pipek1Error::WireCorruption("Invalid magic bytes (expected PK01)".into()));
    }
    if header[4] != 0x01 {
        return Err(Pipek1Error::WireCorruption(format!("Unsupported protocol version: {}", header[4])));
    }
    let mode = header[5];
    if mode != 0x01 && mode != 0x02 {
        return Err(Pipek1Error::WireCorruption(format!("Unsupported mode: {}", mode)));
    }

    // Anti-Bypass Invariant: If --sender is provided and wire header is Mode 0x02 (Anonymous), abort
    if expected_sender.is_some() && mode == 0x02 {
        return Err(Pipek1Error::WireCorruption("Sender verification requested via --sender, but wire header indicates Mode 2 (Anonymous)".into()));
    }

    if mode == 0x01 && expected_sender.is_none() && !allow_untrusted_sender {
        return Err(Pipek1Error::UsageError("Mode 1 stream requires either --sender <npub|hex> or --allow-untrusted-sender".into()));
    }

    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(&header[6..38]);

    let mut recip_pub = [0u8; 32];
    recip_pub.copy_from_slice(&header[38..70]);

    if recip_pub != expected_recip_pub {
        return Err(Pipek1Error::WireCorruption("Recipient public key mismatch on wire".into()));
    }

    let mut salt = [0u8; 11];
    salt.copy_from_slice(&header[70..81]);

    // 2. Compute ECDH and verify Header HMAC
    let ikm = ecdh_shared_x(&recip_priv, &eph_pub)
        .map_err(|e| Pipek1Error::WireCorruption(format!("ECDH calculation failed: {}", e)))?;
    let (header_key, payload_key) = derive_keys(&ikm, &salt)
        .map_err(|e| Pipek1Error::WireCorruption(format!("Key derivation failed: {}", e)))?;

    let expected_hmac = compute_header_hmac(&header_key, &header[0..81]);
    if bool::from(!expected_hmac.ct_eq(&header[81..97])) {
        return Err(Pipek1Error::WireCorruption("Header HMAC verification failed (tampered wire header)".into()));
    }

    // 3. Spool-and-verify decrypt engine (Bounded RAM + AEAD Disk Spooling)
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&payload_key));
    let mut chunk_counter: u64 = 0;
    let mut spooler = StreamSpooler::new(max_size);
    let mut plaintext_hasher = Sha256::new();
    let mut stdout = io::stdout();

    loop {
        let mut chunk_hdr = [0u8; CHUNK_HEADER_SIZE];
        match stdin.read_exact(&mut chunk_hdr) {
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(Pipek1Error::WireCorruption("Premature EOF before terminal chunk".into()));
            }
            Err(e) => return Err(Pipek1Error::Io(e)),
        }

        let chunk_len = u32::from_be_bytes(chunk_hdr[0..4].try_into().unwrap()) as usize;
        let term_tag = chunk_hdr[4];

        if term_tag != 0x00 && term_tag != 0x01 {
            return Err(Pipek1Error::WireCorruption(format!("Framing violation: invalid terminal tag 0x{:02x} (expected 0x00 or 0x01)", term_tag)));
        }
        if term_tag == 0x00 && chunk_len != CHUNK_SIZE {
            return Err(Pipek1Error::WireCorruption("Framing violation: intermediate chunk must be exactly 64 KiB".into()));
        }
        if chunk_len > CHUNK_SIZE {
            return Err(Pipek1Error::WireCorruption("Chunk size exceeds 64 KiB buffer limit".into()));
        }

        let mut ct_buffer = vec![0u8; chunk_len];
        stdin.read_exact(&mut ct_buffer)?;

        let mut tag_bytes = [0u8; TAG_SIZE];
        stdin.read_exact(&mut tag_bytes)?;

        let nonce_bytes = build_nonce(chunk_counter, term_tag);
        let aad = build_aad(MAGIC_HEADER, 0x01, mode, &recip_pub, chunk_len as u32, chunk_counter, term_tag);

        let tag = Tag::from_slice(&tag_bytes);
        if cipher.decrypt_in_place_detached(&nonce_bytes.into(), &aad, &mut ct_buffer, tag).is_err() {
            return Err(Pipek1Error::WireCorruption("Poly1305 AEAD tag verification failed (tampered chunk)".into()));
        }

        if mode == 0x01 {
            plaintext_hasher.update(&ct_buffer);
        }

        if allow_unverified_stream {
            stdout.write_all(&ct_buffer)?;
            stdout.flush()?;
        } else if let Err(e) = spooler.write_chunk(&ct_buffer) {
            return Err(Pipek1Error::UsageError(e));
        }
        chunk_counter += 1;

        if term_tag == 0x01 {
            break;
        }
    }

    // 4. Mode 1 Authenticated Trailer Verification (96 bytes: SenderPub [32B] || BIP340-Sig [64B])
    if mode == 0x01 {
        let mut trailer = [0u8; TRAILER_SIZE];
        if let Err(e) = stdin.read_exact(&mut trailer) {
            return Err(Pipek1Error::WireCorruption(format!("Missing or truncated Mode 1 authenticated trailer: {}", e)));
        }

        let sender_pub = &trailer[0..32];
        let sig_bytes = &trailer[32..96];

        let sender_vk = match VerifyingKey::from_bytes(sender_pub) {
            Ok(k) => k,
            Err(e) => {
                return Err(Pipek1Error::WireCorruption(format!("Invalid sender public key in trailer: {}", e)));
            }
        };

        let sig = match Signature::try_from(sig_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(Pipek1Error::WireCorruption(format!("Invalid signature framing in trailer: {}", e)));
            }
        };

        let pt_digest = plaintext_hasher.finalize();
        let mut auth_transcript = [0u8; 48];
        auth_transcript[0..16].copy_from_slice(&header[81..97]); // header HMAC
        auth_transcript[16..48].copy_from_slice(&pt_digest);

        let auth_hash = tagged_hash(TAG_AUTH, &auth_transcript);

        if let Err(e) = sender_vk.verify_raw(&auth_hash, &sig) {
            return Err(Pipek1Error::AuthFailure(format!("Mode 1 trailer signature verification failed: {}", e)));
        }

        let sender_npub = encode_npub(sender_pub);

        if let Some(exp) = expected_sender {
            let exp_bytes = parse_key_bytes(&exp).map_err(Pipek1Error::UsageError)?;
            if exp_bytes != sender_pub {
                return Err(Pipek1Error::AuthFailure(format!("Authenticated sender {} does not match expected sender {}", sender_npub, exp)));
            }
            eprintln!("Notice: Authenticated Mode 1 stream verified from {}", sender_npub);
        } else if allow_untrusted_sender {
            eprintln!("Notice: Decrypted Mode 1 stream authenticated by untrusted sender {}", sender_npub);
        }
    }

    // 5. Post-stream EOF validation (assert zero unauthenticated trailing bytes)
    let mut trailing = [0u8; 1];
    if stdin.read(&mut trailing)? > 0 {
        return Err(Pipek1Error::WireCorruption("Unauthenticated trailing bytes detected after stream termination".into()));
    }

    // 6. Release verified plaintext to stdout (Zero RUP Invariant achieved)
    if !allow_unverified_stream {
        spooler.release_to(&mut stdout)?;
    }
    Ok(())
}

/// Resolves repository trust database (allowed_signers)
pub fn resolve_allowed_signers() -> Vec<(String, [u8; 32])> {
    let mut signers = Vec::new();
    let mut candidate_paths = Vec::new();

    // Check git config pipek1.allowedSignersFile
    if let Ok(output) = std::process::Command::new("git").args(["config", "--get", "pipek1.allowedSignersFile"]).output() {
        if output.status.success() {
            let p = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !p.is_empty() {
                candidate_paths.push(PathBuf::from(p));
            }
        }
    }

    // Check git config pipek1.allowInTreeSigners (default: true)
    let allow_in_tree = match std::process::Command::new("git").args(["config", "--bool", "--get", "pipek1.allowInTreeSigners"]).output() {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
            s != "false"
        }
        _ => true,
    };

    if allow_in_tree {
        if let Ok(git_dir) = env::var("GIT_DIR") {
            candidate_paths.push(PathBuf::from(git_dir).join("pipek1_signers"));
        }

        // Ascend current working directory to find repository root (.git)
        if let Ok(mut curr) = env::current_dir() {
            loop {
                let dot_git = curr.join(".git");
                if dot_git.is_dir() {
                    candidate_paths.push(dot_git.join("pipek1_signers"));
                    break;
                } else if dot_git.is_file() {
                    if let Ok(content) = fs::read_to_string(&dot_git) {
                        for line in content.lines() {
                            if let Some(rest) = line.strip_prefix("gitdir:") {
                                let mut gitdir_path = PathBuf::from(rest.trim());
                                if !gitdir_path.is_absolute() {
                                    gitdir_path = curr.join(gitdir_path);
                                }
                                candidate_paths.push(gitdir_path.join("pipek1_signers"));
                                let commondir_file = gitdir_path.join("commondir");
                                if let Ok(cd_content) = fs::read_to_string(&commondir_file) {
                                    let mut common = PathBuf::from(cd_content.trim());
                                    if !common.is_absolute() {
                                        common = gitdir_path.join(common);
                                    }
                                    if let Ok(canon) = common.canonicalize() {
                                        candidate_paths.push(canon.join("pipek1_signers"));
                                    } else {
                                        candidate_paths.push(common.join("pipek1_signers"));
                                    }
                                }
                            }
                        }
                    }
                    break;
                }
                if !curr.pop() {
                    break;
                }
            }
        }
    }

    if let Ok(home) = env::var("HOME") {
        candidate_paths.push(PathBuf::from(home).join(".config/pipek1/allowed_signers"));
    }

    for path in candidate_paths {
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
                    if tokens.is_empty() {
                        continue;
                    }
                    let key_token = tokens[tokens.len() - 1];
                    if let Ok(key_bytes) = parse_key_bytes(key_token) {
                        let identity = if tokens.len() > 1 {
                            tokens[0..tokens.len() - 1].join(" ")
                        } else {
                            encode_npub(&key_bytes)
                        };
                        if !signers.iter().any(|(_, k)| *k == key_bytes) {
                            signers.push((identity, key_bytes));
                        }
                    }
                }
            }
        }
    }
    signers
}

fn write_status_fd(status_fd: Option<i32>, line: &str) {
    if let Some(fd_num) = status_fd {
        if fd_num == 1 {
            let mut stdout = io::stdout();
            let _ = stdout.write_all(line.as_bytes());
            let _ = stdout.flush();
            return;
        } else if fd_num == 2 {
            let mut stderr = io::stderr();
            let _ = stderr.write_all(line.as_bytes());
            let _ = stderr.flush();
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::io::FromRawFd;
            unsafe {
                let mut f = fs::File::from_raw_fd(fd_num);
                let _ = f.write_all(line.as_bytes());
                let _ = f.flush();
                std::mem::forget(f); // prevent closing inherited fd
            }
        }
    }
}

/// Git Plumbing Shim Handler
pub fn run_git_shim(args: &[String]) -> Result<(), Pipek1Error> {
    let mut status_fd: Option<i32> = None;
    let mut key_id: Option<String> = None;
    let mut is_verify = false;
    let mut verify_sig_path: Option<String> = None;
    let mut verify_data_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with("--status-fd=") {
            let num = arg.strip_prefix("--status-fd=").unwrap();
            status_fd = num.parse().ok();
        } else if arg == "--status-fd" {
            if i + 1 < args.len() {
                status_fd = args[i + 1].parse().ok();
                i += 1;
            }
        } else if arg == "--verify" || arg == "-v" {
            is_verify = true;
            if i + 1 < args.len() {
                verify_sig_path = Some(args[i + 1].clone());
                i += 1;
            }
            if i + 1 < args.len() {
                verify_data_path = Some(args[i + 1].clone());
                i += 1;
            }
        } else if arg == "-u" {
            if i + 1 < args.len() {
                key_id = Some(args[i + 1].clone());
                i += 1;
            }
        } else if arg.starts_with("-u") && arg.len() > 2 {
            key_id = Some(arg[2..].to_string());
        } else if arg.contains('u') && arg.starts_with('-') && !arg.starts_with("--") {
            // e.g. -bsau <keyid>
            if i + 1 < args.len() {
                key_id = Some(args[i + 1].clone());
                i += 1;
            }
        }
        i += 1;
    }

    if is_verify {
        // Verification protocol
        let sig_p = verify_sig_path.ok_or_else(|| Pipek1Error::UsageError("Missing signature path for --verify".into()))?;
        let data_p = verify_data_path.unwrap_or_else(|| "-".to_string());

        let sig_raw = fs::read(&sig_p).map_err(|e| Pipek1Error::UsageError(format!("Cannot read signature: {}", e)))?;
        // Detach ASCII armor if present
        let sig_bytes = if let Ok(s) = std::str::from_utf8(&sig_raw) {
            if s.contains("BEGIN PGP SIGNATURE") {
                let mut b64 = String::new();
                let mut capture = false;
                for line in s.lines() {
                    let tr = line.trim();
                    if tr.contains("BEGIN PGP SIGNATURE") {
                        capture = true;
                        continue;
                    }
                    if tr.contains("END PGP SIGNATURE") {
                        break;
                    }
                    if capture && !tr.is_empty() && !tr.contains(':') {
                        b64.push_str(tr);
                    }
                }
                base64::engine::general_purpose::STANDARD.decode(b64)
                    .map_err(|e| Pipek1Error::WireCorruption(format!("Base64 decode error: {}", e)))?
            } else {
                sig_raw
            }
        } else {
            sig_raw
        };

        if sig_bytes.len() != SIGNATURE_PAYLOAD_SIZE {
            write_status_fd(status_fd, "[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG 0000000000000000 1 8 00 0000000000 9\n");
            eprintln!("pipek1-git-shim: error: malformed or unrecognized signature format");
            return Err(Pipek1Error::WireCorruption("malformed or unrecognized signature format".into()));
        }

        let mut sig_payload = [0u8; SIGNATURE_PAYLOAD_SIZE];
        sig_payload.copy_from_slice(&sig_bytes);

        let data_bytes = if data_p == "-" {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            buf
        } else {
            fs::read(&data_p)?
        };

        let msg_digest: [u8; 32] = Sha256::digest(&data_bytes).into();

        match verify_stream_payload(&sig_payload, &msg_digest) {
            Ok(signer_pk) => {
                let hex_pk = hex::encode(signer_pk);
                let npub = encode_npub(&signer_pk);
                let timestamp = u32::from_be_bytes(sig_payload[5..9].try_into().unwrap());
                let days = timestamp / 86400;
                // Civil date computation from Unix days (epoch 1970-01-01)
                let z = days as i64 + 719468;
                let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
                let doe = (z - era * 146097) as u32;
                let yoe = (doe - doe / 1024 + doe / 1461 - doe / 142401) / 365;
                let y = yoe as i64 + era * 400;
                let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
                let mp = (5 * doy + 2) / 153;
                let d = doy - (153 * mp + 2) / 5 + 1;
                let m = if mp < 10 { mp + 3 } else { mp - 9 };
                let y_final = if m <= 2 { y + 1 } else { y };
                let date_str = format!("{:04}-{:02}-{:02}", y_final, m, d);

                let allowed = resolve_allowed_signers();
                let matched_identity = allowed.iter().find(|(_, k)| *k == signer_pk);

                write_status_fd(status_fd, "[GNUPG:] NEWSIG\n");
                if let Some((ident, _)) = matched_identity {
                    eprintln!("gpg: Signature made {} using secp256k1 key {}", date_str, hex_pk);
                    eprintln!("gpg: Good signature from \"{}\" [ultimate]", ident);
                    write_status_fd(status_fd, &format!("[GNUPG:] GOODSIG {} {}\n", hex_pk, ident));
                    write_status_fd(status_fd, &format!("[GNUPG:] VALIDSIG {} {} {} 0 4 0 1 8 00 {}\n", hex_pk, date_str, timestamp, hex_pk));
                    write_status_fd(status_fd, "[GNUPG:] TRUST_ULTIMATE 0 pgp\n");
                } else {
                    eprintln!("gpg: Signature made {} using secp256k1 key {}", date_str, hex_pk);
                    eprintln!("gpg: Good signature from \"{}\" [unknown]", npub);
                    write_status_fd(status_fd, &format!("[GNUPG:] GOODSIG {} {}\n", hex_pk, npub));
                    write_status_fd(status_fd, &format!("[GNUPG:] VALIDSIG {} {} {} 0 4 0 1 8 00 {}\n", hex_pk, date_str, timestamp, hex_pk));
                    write_status_fd(status_fd, "[GNUPG:] TRUST_UNDEFINED 0 pgp\n");
                }
                Ok(())
            }
            Err(e) => {
                let signer_pk = &sig_payload[9..41];
                let hex_pk = hex::encode(signer_pk);
                let npub = encode_npub(signer_pk);
                write_status_fd(status_fd, "[GNUPG:] NEWSIG\n");
                write_status_fd(status_fd, &format!("[GNUPG:] BADSIG {} {}\n", hex_pk, npub));
                eprintln!("pipek1-git-shim: signature verification failed: {}", e);
                Err(Pipek1Error::AuthFailure(format!("signature verification failed: {}", e)))
            }
        }
    } else {
        // Signing protocol (git commit -S)
        let sk_bytes = load_secret_key(&KeyIntakeArgs::default())?;
        let signing_key = SigningKey::from_bytes(&sk_bytes)
            .map_err(|e| Pipek1Error::UsageError(format!("Invalid secp256k1 secret key: {}", e)))?;
        let pk_x = signing_key.verifying_key().to_bytes();
        let hex_pk = hex::encode(pk_x);

        if let Some(ref kid) = key_id {
            if let Ok(exp_bytes) = parse_key_bytes(kid) {
                if exp_bytes != pk_x.as_slice() {
                    write_status_fd(status_fd, &format!("[GNUPG:] INV_SGNR 0 {}\n", kid));
                    eprintln!("pipek1-git-shim: error: signing key {} does not match configured secret key", kid);
                    return Err(Pipek1Error::UsageError(format!("signing key {} does not match configured secret key", kid)));
                }
            }
        }

        let mut commit_data = Vec::new();
        io::stdin().read_to_end(&mut commit_data)?;
        let msg_digest: [u8; 32] = Sha256::digest(&commit_data).into();

        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|e| Pipek1Error::UsageError(format!("Clock error: {}", e)))?
            .as_secs() as u32;
        let sig_payload = sign_stream_payload(&signing_key, &msg_digest, now);

        if let Some(fd_num) = status_fd {
            write_status_fd(Some(fd_num), &format!("[GNUPG:] SIG_CREATED D 1 8 00 {} {}\n", now, hex_pk));
        }

        let b64_sig = base64::engine::general_purpose::STANDARD.encode(sig_payload);
        println!("-----BEGIN PGP SIGNATURE-----");
        println!();
        println!("{}", b64_sig);
        println!("-----END PGP SIGNATURE-----");
        Ok(())
    }
}

fn parse_key_intake_args(args: &[String], start_idx: usize) -> (KeyIntakeArgs, usize) {
    let mut key_args = KeyIntakeArgs::default();
    let mut i = start_idx;
    while i < args.len() {
        match args[i].as_str() {
            "--sec-fd" => {
                if i + 1 < args.len() {
                    key_args.sec_fd = args[i + 1].parse().ok();
                    i += 1;
                }
            }
            "--sec-file" => {
                if i + 1 < args.len() {
                    key_args.sec_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--mnemonic-fd" => {
                if i + 1 < args.len() {
                    key_args.mnemonic_fd = args[i + 1].parse().ok();
                    i += 1;
                }
            }
            "--passphrase-fd" => {
                if i + 1 < args.len() {
                    key_args.passphrase_fd = args[i + 1].parse().ok();
                    i += 1;
                }
            }
            "--bip85-identity" if i + 1 < args.len() => {
                key_args.bip85_identity = args[i + 1].parse().ok();
                i += 1;
            }
            "--bip85-index" if i + 1 < args.len() => {
                key_args.bip85_index = args[i + 1].parse().ok();
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    (key_args, i)
}

fn print_usage() {
    eprintln!("pipek1 v0.1.0 - Stateless secp256k1 UNIX cryptographic stream filter");
    eprintln!("Usage:");
    eprintln!("  pipek1 encrypt --recipient <npub|hex> [--entropy-fd <N>]  # Authenticated stream encryption");
    eprintln!("  pipek1 decrypt                                           # Spool-and-verify stream decryption");
    eprintln!("  pipek1 sign                                              # Sign stdin stream using PIPEK1_SEC_KEY env");
    eprintln!("  pipek1 verify --sig <file> [--pub <npub|hex>]            # Verify stdin stream against signature file");
    eprintln!("  pipek1 pubkey                                            # Display public key and npub from PIPEK1_SEC_KEY");
    eprintln!("  pipek1 hash [tag]                                        # Compute BIP-340 tagged hash over stdin");
    eprintln!("  pipek1 inspect-header                                    # Parse 97-byte wire header from stdin");
    eprintln!("  pipek1 inspect-chunk                                     # Parse 5-byte chunk framing header from stdin");
}

fn dispatch_command(args: &[String]) -> Result<(), Pipek1Error> {
    match args[1].as_str() {
        "encrypt" => {
            let mut recipient = None;
            let mut mode = 0x02; // Default anonymous mode
            let mut entropy_fd = None;
            let (key_args, _) = parse_key_intake_args(args, 2);
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--recipient" => {
                        if i + 1 < args.len() {
                            recipient = Some(args[i + 1].clone());
                            i += 1;
                        }
                    }
                    "--mode" => {
                        if i + 1 < args.len() {
                            mode = args[i + 1].parse().unwrap_or(2);
                            i += 1;
                        }
                    }
                    "--entropy-fd" if i + 1 < args.len() => {
                        entropy_fd = args[i + 1].parse().ok();
                        i += 1;
                    }
                    _ => {}
                }
                i += 1;
            }
            let recip = recipient.ok_or_else(|| Pipek1Error::UsageError("Missing mandatory argument: --recipient <npub|hex>".into()))?;
            run_encrypt(&recip, mode, &key_args, entropy_fd)
        }
        "decrypt" => {
            let mut sender = None;
            let mut allow_untrusted = false;
            let mut allow_unverified = false;
            let mut max_size = None;
            let (key_args, _) = parse_key_intake_args(args, 2);
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--sender" if i + 1 < args.len() => {
                        sender = Some(args[i + 1].clone());
                        i += 1;
                    }
                    "--allow-untrusted-sender" => {
                        allow_untrusted = true;
                    }
                    "--allow-unverified-stream" => {
                        allow_unverified = true;
                    }
                    "--max-size" if i + 1 < args.len() => {
                        max_size = args[i + 1].parse().ok();
                        i += 1;
                    }
                    _ => {}
                }
                i += 1;
            }
            run_decrypt(sender, allow_untrusted, allow_unverified, max_size, &key_args)
        }
        "pubkey" => {
            let (key_args, _) = parse_key_intake_args(args, 2);
            let sk_bytes = load_secret_key(&key_args)?;
            let signing_key = SigningKey::from_bytes(&sk_bytes)
                .map_err(|e| Pipek1Error::UsageError(format!("Invalid secp256k1 secret key: {}", e)))?;
            let pk_x = signing_key.verifying_key().to_bytes();
            let npub = encode_npub(pk_x.as_slice());
            println!("Hex:  {}", hex::encode(pk_x));
            println!("Npub: {}", npub);
            Ok(())
        }
        "sign" => {
            let (key_args, _) = parse_key_intake_args(args, 2);
            let sk_bytes = load_secret_key(&key_args)?;
            let signing_key = SigningKey::from_bytes(&sk_bytes)
                .map_err(|e| Pipek1Error::UsageError(format!("Invalid secp256k1 secret key: {}", e)))?;

            let mut stdin = io::stdin();
            let mut chunk_buf = vec![0u8; CHUNK_SIZE];
            let mut hasher = Sha256::new();
            loop {
                let n = stdin.read(&mut chunk_buf)?;
                if n == 0 { break; }
                hasher.update(&chunk_buf[..n]);
            }
            let msg_digest: [u8; 32] = hasher.finalize().into();

            let now = SystemTime::now().duration_since(UNIX_EPOCH)
                .map_err(|e| Pipek1Error::UsageError(format!("Clock error: {}", e)))?
                .as_secs() as u32;
            let sig_payload = sign_stream_payload(&signing_key, &msg_digest, now);

            io::stdout().write_all(&sig_payload)?;
            Ok(())
        }
        "verify" => {
            let mut sig_path = None;
            let mut expected_pub = None;
            let mut max_size = None;
            let mut pass_through = false;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--sig" => {
                        if i + 1 < args.len() {
                            sig_path = Some(args[i + 1].clone());
                            i += 1;
                        }
                    }
                    "--pub" => {
                        if i + 1 < args.len() {
                            expected_pub = Some(args[i + 1].clone());
                            i += 1;
                        }
                    }
                    "--pass-through" => {
                        pass_through = true;
                    }
                    "--max-size" if i + 1 < args.len() => {
                        max_size = args[i + 1].parse().ok();
                        i += 1;
                    }
                    _ => {}
                }
                i += 1;
            }

            if pass_through && expected_pub.is_none() {
                return Err(Pipek1Error::UsageError("--pub <npub|hex> is mandatory when --pass-through is enabled".into()));
            }

            let path = sig_path.ok_or_else(|| Pipek1Error::UsageError("Missing mandatory argument: --sig <file>".into()))?;
            let sig_raw = std::fs::read(&path)
                .map_err(|e| Pipek1Error::UsageError(format!("Failed to read signature file '{}': {}", path, e)))?;

            // Detach ASCII armor if present
            let sig_bytes = if let Ok(s) = std::str::from_utf8(&sig_raw) {
                if s.contains("BEGIN PGP SIGNATURE") {
                    let mut b64 = String::new();
                    let mut capture = false;
                    for line in s.lines() {
                        let tr = line.trim();
                        if tr.contains("BEGIN PGP SIGNATURE") {
                            capture = true;
                            continue;
                        }
                        if tr.contains("END PGP SIGNATURE") {
                            break;
                        }
                        if capture && !tr.is_empty() && !tr.contains(':') {
                            b64.push_str(tr);
                        }
                    }
                    base64::engine::general_purpose::STANDARD.decode(b64)
                        .map_err(|e| Pipek1Error::WireCorruption(format!("Base64 decode error: {}", e)))?
                } else {
                    sig_raw
                }
            } else {
                sig_raw
            };

            if sig_bytes.len() != SIGNATURE_PAYLOAD_SIZE {
                return Err(Pipek1Error::WireCorruption(format!("Signature payload must be exactly {} bytes (got {})", SIGNATURE_PAYLOAD_SIZE, sig_bytes.len())));
            }

            let mut payload = [0u8; SIGNATURE_PAYLOAD_SIZE];
            payload.copy_from_slice(&sig_bytes);

            let mut spooler = if pass_through {
                Some(StreamSpooler::new(max_size))
            } else {
                None
            };
            let mut stdin = io::stdin();
            let mut chunk_buf = vec![0u8; CHUNK_SIZE];
            let mut hasher = Sha256::new();
            loop {
                let n = stdin.read(&mut chunk_buf)?;
                if n == 0 { break; }
                hasher.update(&chunk_buf[..n]);
                if let Some(ref mut s) = spooler {
                    if let Err(e) = s.write_chunk(&chunk_buf[..n]) {
                        return Err(Pipek1Error::UsageError(e));
                    }
                }
            }
            let msg_digest: [u8; 32] = hasher.finalize().into();

            match verify_stream_payload(&payload, &msg_digest) {
                Ok(signer_pk) => {
                    let signer_npub = encode_npub(&signer_pk);
                    if let Some(exp) = expected_pub {
                        let exp_pk = parse_key_bytes(&exp).map_err(Pipek1Error::UsageError)?;
                        if exp_pk != signer_pk {
                            return Err(Pipek1Error::AuthFailure(format!("Signer key {} does not match expected key {}", signer_npub, exp)));
                        }
                    } else {
                        eprintln!("Notice: Verifying against embedded untrusted pubkey {}", signer_npub);
                    }

                    if let Some(s) = spooler {
                        let mut stdout = io::stdout();
                        s.release_to(&mut stdout)?;
                    } else {
                        eprintln!("Notice: Cryptographic verification SUCCESS from {}", signer_npub);
                    }
                    Ok(())
                }
                Err(e) => {
                    Err(Pipek1Error::AuthFailure(format!("Verification FAILED: {}", e)))
                }
            }
        }
        "hash" => {
            let tag = if args.len() > 2 { &args[2] } else { TAG_SIGN };
            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer)?;
            let th = tagged_hash(tag, &buffer);
            println!("{}", hex::encode(th));
            Ok(())
        }
        "inspect-header" => {
            let mut header = [0u8; WIRE_HEADER_SIZE];
            io::stdin().read_exact(&mut header)?;
            if &header[0..4] != MAGIC_HEADER {
                return Err(Pipek1Error::WireCorruption("Invalid magic bytes (expected PK01)".into()));
            }
            println!("Valid pipek1 Wire Header (97 bytes):");
            println!("  Magic:        {}", String::from_utf8_lossy(&header[0..4]));
            println!("  Version:      0x{:02x}", header[4]);
            println!("  Mode:         0x{:02x}", header[5]);
            println!("  EphemeralPub: {}", hex::encode(&header[6..38]));
            println!("  RecipientPub: {}", hex::encode(&header[38..70]));
            println!("  Salt (11B):   {}", hex::encode(&header[70..81]));
            println!("  HMAC (16B):   {}", hex::encode(&header[81..97]));
            Ok(())
        }
        "inspect-chunk" => {
            let mut chunk_hdr = [0u8; CHUNK_HEADER_SIZE];
            io::stdin().read_exact(&mut chunk_hdr)?;
            let len = u32::from_be_bytes(chunk_hdr[0..4].try_into().unwrap());
            let term = chunk_hdr[4];
            println!("Valid pipek1 Chunk Header (5 bytes):");
            println!("  Payload Length: {} bytes", len);
            println!("  Terminal Tag:   0x{:02x} ({})", term, if term == 0x01 { "TERMINAL" } else { "INTERMEDIATE" });
            Ok(())
        }
        _ => {
            print_usage();
            Err(Pipek1Error::UsageError("Unknown command".into()))
        }
    }
}

fn real_main() -> i32 {
    #[cfg(target_os = "linux")]
    unsafe {
        // Disable core dumps and ptrace inspection across all command invocations immediately
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return 2;
    }

    let exe_name = args[0].rsplit('/').next().unwrap_or(&args[0]);
    let is_git_invocation = exe_name.contains("git-shim")
        || args[1] == "git-shim"
        || args[1].starts_with("-b")
        || args[1].starts_with("--status-fd")
        || args[1].starts_with("--keyid-format")
        || args[1] == "--verify"
        || args[1].starts_with("--extra-check-level");

    let res = if is_git_invocation {
        let shim_args = if args[1] == "git-shim" { &args[2..] } else { &args[1..] };
        run_git_shim(shim_args)
    } else {
        dispatch_command(&args)
    };

    match res {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("Error: {}", err);
            err.exit_code()
        }
    }
}

fn main() {
    let exit_code = real_main();
    std::process::exit(exit_code);
}
