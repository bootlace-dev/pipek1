// SPDX-License-Identifier: MIT
// Copyright (c) 2026 bootlace-dev

//! Spool-and-Verify Engine: Bounded RAM (<= 16 MiB) with Ephemeral AEAD Disk Spilling
//! Autonomous / Zero-PII Invariant: bootlace-dev <bootlace-dev@users.noreply.github.com>

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Tag};
use rand::{rngs::OsRng, RngCore};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use zeroize::Zeroize;

pub const MEMORY_SPOOL_LIMIT: usize = 16 * 1024 * 1024; // 16 MiB
pub const SPOOL_CHUNK_SIZE: usize = 64 * 1024;           // 64 KiB canonical block size
pub const SPOOL_TAG_SIZE: usize = 16;                    // Poly1305 16-byte tag

/// Ephemeral encrypted spooler for multi-gigabyte streams
pub struct StreamSpooler {
    mem_buffer: Vec<u8>,
    disk_file: Option<File>,
    spool_key: [u8; 32],
    block_counter: u64,
    total_bytes: u64,
    max_size: Option<u64>,
}

impl StreamSpooler {
    pub fn new(max_size: Option<u64>) -> Self {
        let mut spool_key = [0u8; 32];
        OsRng.fill_bytes(&mut spool_key);
        Self {
            mem_buffer: Vec::with_capacity(std::cmp::min(MEMORY_SPOOL_LIMIT, 64 * 1024)),
            disk_file: None,
            spool_key,
            block_counter: 0,
            total_bytes: 0,
            max_size,
        }
    }

    fn open_anonymous_tmpfile() -> io::Result<File> {
        let tmp_dir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        #[cfg(target_os = "linux")]
        {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::io::FromRawFd;

            let c_path = CString::new(std::path::Path::new(&tmp_dir).as_os_str().as_bytes())?;
            let flags = libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC;
            let fd = unsafe { libc::open(c_path.as_ptr(), flags, 0o600) };
            if fd >= 0 {
                return Ok(unsafe { File::from_raw_fd(fd) });
            }
        }

        // Fallback: Named temp file created with mode 0600 and unlinked immediately
        let tmp_path = format!("{}/.pipek1_spool_{}_{}", tmp_dir, std::process::id(), OsRng.next_u64());
        let mut opts = fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let f = opts.open(&tmp_path)?;

        #[cfg(unix)]
        {
            let _ = fs::remove_file(&tmp_path); // Unlink immediately: descriptor remains open and private
        }
        Ok(f)
    }

    fn build_spool_nonce(block_counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&block_counter.to_be_bytes());
        // bytes 8..11 are 0x00
        nonce
    }

    fn build_spool_aad(block_counter: u64, len: u32) -> [u8; 12] {
        let mut aad = [0u8; 12];
        aad[0..8].copy_from_slice(&block_counter.to_be_bytes());
        aad[8..12].copy_from_slice(&len.to_be_bytes());
        aad
    }

    fn flush_single_block_to_disk(&mut self, data: &[u8]) -> io::Result<()> {
        if self.disk_file.is_none() {
            self.disk_file = Some(Self::open_anonymous_tmpfile()?);
        }
        let file = self.disk_file.as_mut().unwrap();

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.spool_key));
        let nonce = Self::build_spool_nonce(self.block_counter);
        let aad = Self::build_spool_aad(self.block_counter, data.len() as u32);

        let mut ct = data.to_vec();
        let tag = cipher.encrypt_in_place_detached(&nonce.into(), &aad, &mut ct)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Spool encrypt error: {}", e)))?;

        // Wire to disk: Len[4B BE] || Ciphertext[L] || Tag[16B]
        file.write_all(&(data.len() as u32).to_be_bytes())?;
        file.write_all(&ct)?;
        file.write_all(&tag)?;

        self.block_counter += 1;
        Ok(())
    }

    pub fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), String> {
        self.total_bytes += chunk.len() as u64;
        if let Some(max) = self.max_size {
            if self.total_bytes > max {
                return Err(format!("Stream exceeded maximum allowed size ceiling ({} bytes)", max));
            }
        }

        if self.disk_file.is_none() && self.mem_buffer.len() + chunk.len() <= MEMORY_SPOOL_LIMIT {
            self.mem_buffer.extend_from_slice(chunk);
        } else {
            // Spill existing memory buffer to disk in 64 KiB blocks to avoid heap spikes
            if !self.mem_buffer.is_empty() {
                let mut old_mem = std::mem::take(&mut self.mem_buffer);
                for block in old_mem.chunks(SPOOL_CHUNK_SIZE) {
                    self.flush_single_block_to_disk(block)
                        .map_err(|e| format!("Spool spill error: {}", e))?;
                }
                old_mem.zeroize();
            }

            // Flush incoming chunk in 64 KiB blocks
            for block in chunk.chunks(SPOOL_CHUNK_SIZE) {
                self.flush_single_block_to_disk(block)
                    .map_err(|e| format!("Spool disk write error: {}", e))?;
            }
        }
        Ok(())
    }

    pub fn release_to<W: Write>(mut self, out: &mut W) -> io::Result<()> {
        if let Some(mut file) = self.disk_file.take() {
            file.seek(SeekFrom::Start(0))?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.spool_key));

            for block_idx in 0..self.block_counter {
                let mut len_bytes = [0u8; 4];
                file.read_exact(&mut len_bytes)?;
                let len = u32::from_be_bytes(len_bytes) as usize;

                if len > SPOOL_CHUNK_SIZE || len == 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid spool block framing header"));
                }

                let mut ct = vec![0u8; len];
                file.read_exact(&mut ct)?;

                let mut tag_bytes = [0u8; SPOOL_TAG_SIZE];
                file.read_exact(&mut tag_bytes)?;
                let tag = Tag::from_slice(&tag_bytes);

                let nonce = Self::build_spool_nonce(block_idx);
                let aad = Self::build_spool_aad(block_idx, len as u32);

                cipher.decrypt_in_place_detached(&nonce.into(), &aad, &mut ct, tag)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Spool disk tampering detected"))?;

                out.write_all(&ct)?;
            }
            out.flush()?;
        } else {
            out.write_all(&self.mem_buffer)?;
            out.flush()?;
        }
        Ok(())
    }
}

impl Drop for StreamSpooler {
    fn drop(&mut self) {
        // Instant Cryptographic Erasure
        self.spool_key.zeroize();
        self.mem_buffer.zeroize();
        self.disk_file = None; // Drops FD: unlinked file immediately reclaimed by OS
    }
}
