// SPDX-License-Identifier: MIT
// Copyright (c) 2026 bootlace-dev

use std::io::Write;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_pipek1");

// Deterministic test keys from golden vectors
const ALICE_PRIV: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const ALICE_PUB: &str = "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
const BOB_PRIV: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const BOB_PUB: &str = "4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766";

#[test]
fn test_cli_usage_no_args() {
    let output = Command::new(BIN).output().expect("Failed to execute pipek1");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn test_pubkey_derivation() {
    let output = Command::new(BIN)
        .arg("pubkey")
        .env("PIPEK1_SEC_KEY", ALICE_PRIV)
        .output()
        .expect("Failed to execute pipek1 pubkey");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(ALICE_PUB));
}

#[test]
fn test_bip340_sign_and_verify_roundtrip() {
    let payload = b"Cryptographic assertion: the root key remains in cold storage.";

    // 1. Sign
    let mut sign_proc = Command::new(BIN)
        .arg("sign")
        .env("PIPEK1_SEC_KEY", ALICE_PRIV)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pipek1 sign");

    sign_proc.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let sign_out = sign_proc.wait_with_output().unwrap();
    assert_eq!(sign_out.status.code(), Some(0));
    let sig_bytes = sign_out.stdout;
    assert_eq!(sig_bytes.len(), 105);

    // Write temp sig
    let sig_path = "/tmp/test_cargo_sign.sig";
    std::fs::write(sig_path, &sig_bytes).unwrap();

    // 2. Verify Success
    let mut verify_proc = Command::new(BIN)
        .args(["verify", "--sig", sig_path, "--pub", ALICE_PUB])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pipek1 verify");

    verify_proc.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let verify_out = verify_proc.wait_with_output().unwrap();
    assert_eq!(verify_out.status.code(), Some(0));

    // 3. Verify Adversarial Bit-Flip (Must Exit 1)
    let mut bad_verify_proc = Command::new(BIN)
        .args(["verify", "--sig", sig_path, "--pub", ALICE_PUB])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pipek1 verify");

    bad_verify_proc.stdin.as_mut().unwrap().write_all(b"Tampered payload bit").unwrap();
    let bad_out = bad_verify_proc.wait_with_output().unwrap();
    assert_eq!(bad_out.status.code(), Some(1));

    let _ = std::fs::remove_file(sig_path);
}

#[test]
fn test_mode2_anonymous_stream_roundtrip() {
    let payload = b"Mode 2 Anonymous Forward-Secret Stream Verification Across Pipe Chunks";

    // 1. Encrypt
    let mut enc_proc = Command::new(BIN)
        .args(["encrypt", "--recipient", BOB_PUB])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pipek1 encrypt");

    enc_proc.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let enc_out = enc_proc.wait_with_output().unwrap();
    assert_eq!(enc_out.status.code(), Some(0));
    let ciphertext = enc_out.stdout;

    // 2. Decrypt
    let mut dec_proc = Command::new(BIN)
        .arg("decrypt")
        .env("PIPEK1_SEC_KEY", BOB_PRIV)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pipek1 decrypt");

    dec_proc.stdin.as_mut().unwrap().write_all(&ciphertext).unwrap();
    let dec_out = dec_proc.wait_with_output().unwrap();
    assert_eq!(dec_out.status.code(), Some(0));
    assert_eq!(dec_out.stdout, payload);
}

#[test]
fn test_mode1_authenticated_stream_roundtrip() {
    let payload = b"Mode 1 Authenticated Stream: Signed Trailer Bound to Plaintext Digest";

    // 1. Encrypt Mode 1
    let mut enc_proc = Command::new(BIN)
        .args(["encrypt", "--mode", "1", "--recipient", BOB_PUB])
        .env("PIPEK1_SEC_KEY", ALICE_PRIV)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pipek1 encrypt");

    enc_proc.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let enc_out = enc_proc.wait_with_output().unwrap();
    assert_eq!(enc_out.status.code(), Some(0));
    let ciphertext = enc_out.stdout;

    // 2. Decrypt Mode 1 with Expected Sender
    let mut dec_proc = Command::new(BIN)
        .args(["decrypt", "--sender", ALICE_PUB])
        .env("PIPEK1_SEC_KEY", BOB_PRIV)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pipek1 decrypt");

    dec_proc.stdin.as_mut().unwrap().write_all(&ciphertext).unwrap();
    let dec_out = dec_proc.wait_with_output().unwrap();
    assert_eq!(dec_out.status.code(), Some(0));
    assert_eq!(dec_out.stdout, payload);
}

#[test]
fn test_mode1_rejected_without_sender_or_allow_untrusted() {
    let payload = b"Unauthenticated Mode 1 Ingestion Guard";

    // Encrypt Mode 1
    let mut enc_proc = Command::new(BIN)
        .args(["encrypt", "--mode", "1", "--recipient", BOB_PUB])
        .env("PIPEK1_SEC_KEY", ALICE_PRIV)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pipek1 encrypt");

    enc_proc.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let ciphertext = enc_proc.wait_with_output().unwrap().stdout;

    // Decrypt without --sender or --allow-untrusted-sender must exit 2
    let mut dec_proc = Command::new(BIN)
        .arg("decrypt")
        .env("PIPEK1_SEC_KEY", BOB_PRIV)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pipek1 decrypt");

    dec_proc.stdin.as_mut().unwrap().write_all(&ciphertext).unwrap();
    let dec_out = dec_proc.wait_with_output().unwrap();
    assert_eq!(dec_out.status.code(), Some(2));
}

#[test]
fn test_mode2_rejected_when_sender_provided() {
    let payload = b"Anti-Bypass Guard: Mode 2 cannot satisfy --sender";

    // Encrypt Mode 2
    let mut enc_proc = Command::new(BIN)
        .args(["encrypt", "--recipient", BOB_PUB])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pipek1 encrypt");

    enc_proc.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let ciphertext = enc_proc.wait_with_output().unwrap().stdout;

    // Decrypt Mode 2 with --sender must exit 1 (tamper/bypass attempt)
    let mut dec_proc = Command::new(BIN)
        .args(["decrypt", "--sender", ALICE_PUB])
        .env("PIPEK1_SEC_KEY", BOB_PRIV)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pipek1 decrypt");

    dec_proc.stdin.as_mut().unwrap().write_all(&ciphertext).unwrap();
    let dec_out = dec_proc.wait_with_output().unwrap();
    assert_eq!(dec_out.status.code(), Some(1));
}

#[test]
fn test_pass_through_requires_pub() {
    let out = Command::new(BIN)
        .args(["verify", "--pass-through", "--sig", "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pipek1 verify");

    let out = verify_proc.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
