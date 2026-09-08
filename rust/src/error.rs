// SPDX-License-Identifier: MIT
// Copyright (c) 2026 bootlace-dev

use std::fmt;

#[derive(Debug)]
pub enum Pipek1Error {
    /// Wire tampering or cryptographic verification failure (exit code 1)
    WireCorruption(String),
    /// Signature or authentication verification failure (exit code 1)
    AuthFailure(String),
    /// CLI argument, configuration, or environment parameter error (exit code 2)
    UsageError(String),
    /// Standard I/O error
    Io(std::io::Error),
}

impl fmt::Display for Pipek1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Pipek1Error::WireCorruption(msg) => write!(f, "Wire corruption: {}", msg),
            Pipek1Error::AuthFailure(msg) => write!(f, "Authentication failure: {}", msg),
            Pipek1Error::UsageError(msg) => write!(f, "Usage error: {}", msg),
            Pipek1Error::Io(err) => write!(f, "I/O error: {}", err),
        }
    }
}

impl std::error::Error for Pipek1Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Pipek1Error::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Pipek1Error {
    fn from(err: std::io::Error) -> Self {
        Pipek1Error::Io(err)
    }
}

impl Pipek1Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Pipek1Error::UsageError(_) => 2,
            Pipek1Error::WireCorruption(_) | Pipek1Error::AuthFailure(_) | Pipek1Error::Io(_) => 1,
        }
    }
}
