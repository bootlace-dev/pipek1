// SPDX-License-Identifier: MIT
// Copyright (c) 2026 bootlace-dev

//! pipek1: Pure Stateless UNIX Cryptographic Filter (Specification v1.9)
//! Anonymous / Zero-PII Invariant: bootlace-dev <bootlace-dev@users.noreply.github.com>

use bech32::{Bech32, Hrp};
use k256::schnorr::signature::Signer;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::env;
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAGIC_HEADER: &[u8; 4] = b"PK01";
pub const MAGIC_SIGNATURE: &[u8; 4] = b"PKSG";
pub const WIRE_HEADER_SIZE: usize = 97;
pub const CHUNK_HEADER_SIZE: usize = 5;
pub const SIGNATURE_PAYLOAD_SIZE: usize = 105;

pub const TAG_SIGN: &str = "pipek1/v1/sign";
pub const TAG_AUTH: &str = "pipek1/v1/auth";

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

fn print_usage() {
    eprintln!("pipek1 v0.1.0 - Stateless secp256k1 UNIX cryptographic stream filter");
    eprintln!("Usage:");
    eprintln!("  pipek1 sign                     # Sign stdin stream using PIPEK1_SEC_KEY env");
    eprintln!("  pipek1 verify --sig <file>      # Verify stdin stream against signature file");
    eprintln!("  pipek1 pubkey                   # Display public key and npub from PIPEK1_SEC_KEY");
    eprintln!("  pipek1 hash [tag]               # Compute BIP-340 tagged hash over stdin");
    eprintln!("  pipek1 inspect-header           # Parse 97-byte wire header from stdin");
    eprintln!("  pipek1 inspect-chunk            # Parse 5-byte chunk framing header from stdin");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(2);
    }

    match args[1].as_str() {
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
