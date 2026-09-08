//! pipek1: Pure Stateless UNIX Cryptographic Filter (Specification v1.9)
//! Anonymous / Zero-PII Invariant: bootlace-dev <bootlace-dev@users.noreply.github.com>

use sha2::{Digest, Sha256};
use std::env;
use std::io::{self, Read, Write};

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

fn print_usage() {
    eprintln!("pipek1 v0.1.0 - Stateless secp256k1 UNIX cryptographic stream filter");
    eprintln!("Usage:");
    eprintln!("  pipek1 hash <tag>               # Compute BIP-340 tagged hash over stdin");
    eprintln!("  pipek1 inspect-header           # Parse and validate 97-byte wire header from stdin");
    eprintln!("  pipek1 inspect-chunk            # Parse 5-byte chunk framing header from stdin");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(2);
    }

    match args[1].as_str() {
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
