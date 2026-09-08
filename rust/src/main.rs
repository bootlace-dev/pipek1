// SPDX-License-Identifier: MIT
// Copyright (c) 2026 bootlace-dev

//! pipek1: Pure Stateless UNIX Cryptographic Filter (Specification v1.9)
//! Anonymous / Zero-PII Invariant: bootlace-dev <bootlace-dev@users.noreply.github.com>

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
use sha2::{Digest, Sha256};
use std::env;
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAGIC_HEADER: &[u8; 4] = b"PK01";
pub const MAGIC_SIGNATURE: &[u8; 4] = b"PKSG";
pub const WIRE_HEADER_SIZE: usize = 97;
pub const CHUNK_HEADER_SIZE: usize = 5;
pub const SIGNATURE_PAYLOAD_SIZE: usize = 105;
pub const CHUNK_SIZE: usize = 65536; // 64 KiB
pub const TAG_SIZE: usize = 16;      // Poly1305 16 bytes

pub const TAG_SIGN: &str = "pipek1/v1/sign";
pub const TAG_AUTH: &str = "pipek1/v1/auth";
pub const INFO_HEADER: &[u8] = b"pipek1/v1/header";
pub const INFO_STREAM: &[u8] = b"pipek1/v1/stream";

type HmacSha256 = Hmac<Sha256>;

/// Computes BIP-340 Tagged Hash: SHA-256(SHA-256(tag) || SHA-256(tag) || msg)
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
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
    Ok(Sha256::digest(&out).into())
}

/// Streaming Encryptor Implementation
pub fn run_encrypt(recipient_hex: &str, mode: u8) -> Result<(), Box<dyn std::error::Error>> {
    let recip_x = parse_key_bytes(recipient_hex)?;
    
    // 1. Generate ephemeral keypair (E_priv, E_pub)
    let mut eph_priv_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut eph_priv_bytes);
    let signing_key = SigningKey::from_bytes(&eph_priv_bytes)?;
    let eph_pub_x: [u8; 32] = signing_key.verifying_key().to_bytes().into();

    // 2. Generate 11-byte random salt
    let mut salt = [0u8; 11];
    OsRng.fill_bytes(&mut salt);

    // 3. Compute ECDH IKM and derive keys
    let ikm = ecdh_shared_x(&eph_priv_bytes, &recip_x)?;
    let (header_key, payload_key) = derive_keys(&ikm, &salt)?;

    // 4. Assemble 97-byte header
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

    // 5. Stream encryption loop (64 KiB chunks with 1-chunk lookahead)
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&payload_key));
    let mut stdin = io::stdin();
    let mut chunk_counter: u64 = 0;

    let mut cur_buf = vec![0u8; CHUNK_SIZE];
    let mut next_buf = vec![0u8; CHUNK_SIZE];

    let mut cur_len = stdin.read(&mut cur_buf)?;

    loop {
        let next_len = stdin.read(&mut next_buf)?;
        let term_tag = if next_len == 0 { 0x01u8 } else { 0x00u8 };

        let chunk_len = cur_len as u32;
        let nonce_bytes = build_nonce(chunk_counter, term_tag);
        let aad = build_aad(MAGIC_HEADER, 0x01, mode, &recip_x, chunk_len, chunk_counter, term_tag);

        let mut chunk_header = [0u8; CHUNK_HEADER_SIZE];
        chunk_header[0..4].copy_from_slice(&chunk_len.to_be_bytes());
        chunk_header[4] = term_tag;
        stdout.write_all(&chunk_header)?;

        let mut block = cur_buf[0..cur_len].to_vec();
        let tag = cipher.encrypt_in_place_detached(&nonce_bytes.into(), &aad, &mut block)
            .map_err(|e| format!("Chunk encryption failed: {}", e))?;

        stdout.write_all(&block)?;
        stdout.write_all(tag.as_slice())?;

        chunk_counter += 1;

        if next_len == 0 {
            break;
        }

        std::mem::swap(&mut cur_buf, &mut next_buf);
        cur_len = next_len;
    }

    stdout.flush()?;
    Ok(())
}

/// Streaming Decryptor Implementation (Spool-and-Verify with Zero RUP Invariant)
pub fn run_decrypt() -> Result<(), Box<dyn std::error::Error>> {
    let sk_raw = env::var("PIPEK1_SEC_KEY")
        .map_err(|_| "Environment variable PIPEK1_SEC_KEY not set")?;
    let recip_priv = parse_key_bytes(&sk_raw)?;
    let signing_key = SigningKey::from_bytes(&recip_priv)?;
    let expected_recip_pub: [u8; 32] = signing_key.verifying_key().to_bytes().into();

    let mut stdin = io::stdin();

    // 1. Read and parse 97-byte wire header
    let mut header = [0u8; WIRE_HEADER_SIZE];
    stdin.read_exact(&mut header).map_err(|e| format!("Failed to read 97-byte header: {}", e))?;

    if &header[0..4] != MAGIC_HEADER {
        eprintln!("Error: Invalid magic bytes (expected PK01)");
        std::process::exit(1);
    }
    if header[4] != 0x01 {
        eprintln!("Error: Unsupported protocol version: {}", header[4]);
        std::process::exit(1);
    }
    let mode = header[5];
    if mode != 0x01 && mode != 0x02 {
        eprintln!("Error: Unsupported mode: {}", mode);
        std::process::exit(1);
    }

    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(&header[6..38]);

    let mut recip_pub = [0u8; 32];
    recip_pub.copy_from_slice(&header[38..70]);

    if recip_pub != expected_recip_pub {
        eprintln!("Error: Recipient public key mismatch on wire");
        std::process::exit(1);
    }

    let mut salt = [0u8; 11];
    salt.copy_from_slice(&header[70..81]);

    // 2. Compute ECDH and verify Header HMAC
    let ikm = ecdh_shared_x(&recip_priv, &eph_pub)?;
    let (header_key, payload_key) = derive_keys(&ikm, &salt)?;

    let expected_hmac = compute_header_hmac(&header_key, &header[0..81]);
    if expected_hmac != header[81..97] {
        eprintln!("Error: Header HMAC verification failed (tampered wire header)");
        std::process::exit(1);
    }

    // 3. Spool-and-verify decrypt engine
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&payload_key));
    let mut chunk_counter: u64 = 0;
    let mut spooled_plaintext: Vec<u8> = Vec::new();

    loop {
        let mut chunk_hdr = [0u8; CHUNK_HEADER_SIZE];
        match stdin.read_exact(&mut chunk_hdr) {
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                eprintln!("Error: Premature EOF before terminal chunk");
                std::process::exit(1);
            }
            Err(e) => return Err(Box::new(e)),
        }

        let chunk_len = u32::from_be_bytes(chunk_hdr[0..4].try_into().unwrap()) as usize;
        let term_tag = chunk_hdr[4];

        if term_tag == 0x00 && chunk_len != CHUNK_SIZE {
            eprintln!("Error: Framing violation: intermediate chunk must be exactly 64 KiB");
            std::process::exit(1);
        }
        if chunk_len > CHUNK_SIZE {
            eprintln!("Error: Chunk size exceeds 64 KiB buffer limit");
            std::process::exit(1);
        }

        let mut ct_buffer = vec![0u8; chunk_len];
        stdin.read_exact(&mut ct_buffer)?;

        let mut tag_bytes = [0u8; TAG_SIZE];
        stdin.read_exact(&mut tag_bytes)?;

        let nonce_bytes = build_nonce(chunk_counter, term_tag);
        let aad = build_aad(MAGIC_HEADER, 0x01, mode, &recip_pub, chunk_len as u32, chunk_counter, term_tag);

        let tag = Tag::from_slice(&tag_bytes);
        if let Err(_) = cipher.decrypt_in_place_detached(&nonce_bytes.into(), &aad, &mut ct_buffer, tag) {
            eprintln!("Error: Poly1305 AEAD tag verification failed (tampered chunk)");
            std::process::exit(1);
        }

        spooled_plaintext.extend_from_slice(&ct_buffer);
        chunk_counter += 1;

        if term_tag == 0x01 {
            break;
        }
    }

    // 4. Post-stream EOF validation (assert zero unauthenticated trailing bytes)
    let mut trailing = [0u8; 1];
    if stdin.read(&mut trailing)? > 0 {
        eprintln!("Error: Unauthenticated trailing bytes detected after terminal chunk");
        std::process::exit(1);
    }

    // 5. Release verified plaintext to stdout (Zero RUP Invariant achieved)
    let mut stdout = io::stdout();
    stdout.write_all(&spooled_plaintext)?;
    stdout.flush()?;
    Ok(())
}

fn print_usage() {
    eprintln!("pipek1 v0.1.0 - Stateless secp256k1 UNIX cryptographic stream filter");
    eprintln!("Usage:");
    eprintln!("  pipek1 encrypt --recipient <npub|hex>  # Authenticated stream encryption to stdout");
    eprintln!("  pipek1 decrypt                         # Spool-and-verify stream decryption to stdout");
    eprintln!("  pipek1 sign                            # Sign stdin stream using PIPEK1_SEC_KEY env");
    eprintln!("  pipek1 verify --sig <file>             # Verify stdin stream against signature file");
    eprintln!("  pipek1 pubkey                          # Display public key and npub from PIPEK1_SEC_KEY");
    eprintln!("  pipek1 hash [tag]                      # Compute BIP-340 tagged hash over stdin");
    eprintln!("  pipek1 inspect-header                  # Parse 97-byte wire header from stdin");
    eprintln!("  pipek1 inspect-chunk                   # Parse 5-byte chunk framing header from stdin");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(2);
    }

    match args[1].as_str() {
        "encrypt" => {
            let mut recipient = None;
            let mut mode = 0x02; // Default anonymous mode
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
                    _ => {}
                }
                i += 1;
            }
            let recip = recipient.ok_or("Missing mandatory argument: --recipient <npub|hex>")?;
            run_encrypt(&recip, mode)?;
            Ok(())
        }
        "decrypt" => {
            run_decrypt()?;
            Ok(())
        }
        "pubkey" => {
            let sk_raw = env::var("PIPEK1_SEC_KEY")
                .map_err(|_| "Environment variable PIPEK1_SEC_KEY not set")?;
            let sk_bytes = parse_key_bytes(&sk_raw)?;
            let signing_key = SigningKey::from_bytes(&sk_bytes)
                .map_err(|e| format!("Invalid secp256k1 secret key: {}", e))?;
            let pk_x = signing_key.verifying_key().to_bytes();
            let npub = encode_npub(pk_x.as_slice());
            println!("Hex:  {}", hex::encode(pk_x));
            println!("Npub: {}", npub);
            Ok(())
        }
        "sign" => {
            let sk_raw = env::var("PIPEK1_SEC_KEY")
                .map_err(|_| "Environment variable PIPEK1_SEC_KEY not set")?;
            let sk_bytes = parse_key_bytes(&sk_raw)?;
            let signing_key = SigningKey::from_bytes(&sk_bytes)
                .map_err(|e| format!("Invalid secp256k1 secret key: {}", e))?;

            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer)?;
            let msg_digest: [u8; 32] = Sha256::digest(&buffer).into();

            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
            let sig_payload = sign_stream_payload(&signing_key, &msg_digest, now);

            io::stdout().write_all(&sig_payload)?;
            Ok(())
        }
        "verify" => {
            let mut sig_path = None;
            let mut expected_pub = None;

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
                    _ => {}
                }
                i += 1;
            }

            let path = sig_path.ok_or("Missing mandatory argument: --sig <file>")?;
            let sig_data = std::fs::read(&path)
                .map_err(|e| format!("Failed to read signature file '{}': {}", path, e))?;

            if sig_data.len() != SIGNATURE_PAYLOAD_SIZE {
                eprintln!("Error: Signature payload must be exactly {} bytes (got {})", SIGNATURE_PAYLOAD_SIZE, sig_data.len());
                std::process::exit(1);
            }

            let mut payload = [0u8; SIGNATURE_PAYLOAD_SIZE];
            payload.copy_from_slice(&sig_data);

            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer)?;
            let msg_digest: [u8; 32] = Sha256::digest(&buffer).into();

            match verify_stream_payload(&payload, &msg_digest) {
                Ok(signer_pk) => {
                    let signer_npub = encode_npub(&signer_pk);
                    if let Some(exp) = expected_pub {
                        let exp_pk = parse_key_bytes(&exp)?;
                        if exp_pk != signer_pk {
                            eprintln!("Error: Signer key {} does not match expected key {}", signer_npub, exp);
                            std::process::exit(1);
                        }
                    }
                    eprintln!("Notice: Cryptographic verification SUCCESS from {}", signer_npub);
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("Verification FAILED: {}", e);
                    std::process::exit(1);
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
                eprintln!("Error: Invalid magic bytes (expected PK01)");
                std::process::exit(1);
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
            std::process::exit(2);
        }
    }
}
