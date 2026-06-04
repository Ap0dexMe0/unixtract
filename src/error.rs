//! Unified error type for unixtract.
//!
//! All fallible operations in unixtract return [`UnixtractError`] instead of
//! panicking with `.unwrap()` or `.expect()`. This module provides a single,
//! well-structured error enum that covers all failure modes encountered during
//! firmware format detection, parsing, decryption, decompression, and
//! extraction.

use std::path::PathBuf;

/// The top-level error type used throughout unixtract.
///
/// Variants are defined for all anticipated error categories. Some may not
/// yet be used in every format module but are available for gradual adoption.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum UnixtractError {
    /// An I/O error occurred (file not found, permission denied, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A file format was detected but the header contents are invalid.
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// The input file's format could not be recognized by any detector.
    #[error("Unrecognized input format")]
    UnrecognizedFormat,

    /// A cryptographic operation (AES, DES, RSA, etc.) failed.
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// A decompression operation (zlib, lzma, lz4, etc.) failed.
    #[error("Decompression error: {0}")]
    Decompression(String),

    /// A required key was not found in the key store.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// A checksum or integrity check failed.
    #[error("Checksum mismatch: expected {expected:#010x}, got {actual:#010x}")]
    ChecksumMismatch { expected: u32, actual: u32 },

    /// A path extracted from a firmware image is unsafe (e.g., contains `..`).
    #[error("Unsafe path in firmware image: {path}")]
    UnsafePath { path: PathBuf },

    /// The format was detected but the specific variant/version is unsupported.
    #[error("Unsupported variant: {0}")]
    UnsupportedVariant(String),

    /// A generic error that doesn't fit the more specific variants.
    #[error("{0}")]
    Other(String),
}

/// Convenience type alias used across the crate.
#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, UnixtractError>;

impl From<String> for UnixtractError {
    fn from(s: String) -> Self {
        UnixtractError::Other(s)
    }
}

impl From<&str> for UnixtractError {
    fn from(s: &str) -> Self {
        UnixtractError::Other(s.to_string())
    }
}

impl From<binrw::Error> for UnixtractError {
    fn from(e: binrw::Error) -> Self {
        UnixtractError::InvalidFormat(format!("Binary parse error: {e}"))
    }
}
