//! Path sanitization utilities.
//!
//! Firmware images often embed file paths (e.g., partition names, file names)
//! that are used directly as output paths. A maliciously crafted firmware image
//! could contain paths like `../../etc/passwd` to write files outside the
//! intended output directory. This module provides sanitization to prevent
//! path traversal attacks.

use std::path::{Component, Path, PathBuf};
use crate::error::{UnixtractError, Result};

/// Sanitize a path extracted from a firmware image to prevent path traversal.
///
/// This function:
/// 1. Removes any leading `/` (absolute path)
/// 2. Removes `..` components that would escape the base directory
/// 3. Removes empty components
/// 4. Collapses redundant `.` components
///
/// Returns the sanitized relative path, or an error if the path would escape
/// the base directory after sanitization.
#[allow(dead_code)]
pub fn sanitize_path(path: &str) -> Result<PathBuf> {
    let raw = Path::new(path);
    let mut sanitized = PathBuf::new();

    for component in raw.components() {
        match component {
            Component::CurDir => {
                // Skip "." components
            }
            Component::Normal(c) => {
                sanitized.push(c);
            }
            Component::ParentDir => {
                // Try to pop the last component, but if we can't, just skip it
                // rather than allowing traversal
                if !sanitized.pop() {
                    // Can't go up — skip the ".." silently
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                // Strip absolute path prefixes
            }
        }
    }

    // Final safety check: verify no ".." remains
    if sanitized.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(UnixtractError::UnsafePath {
            path: PathBuf::from(path),
        });
    }

    Ok(sanitized)
}

/// Construct a safe output path by joining a base directory with a sanitized
/// filename or relative path extracted from firmware.
///
/// Returns an error if the resulting path would be outside `base_dir`.
#[allow(dead_code)]
pub fn safe_output_path(base_dir: &Path, firmware_path: &str) -> Result<PathBuf> {
    let sanitized = sanitize_path(firmware_path)?;
    let result = base_dir.join(&sanitized);

    // Verify the result doesn't escape the base directory
    let result_str = result.to_string_lossy();
    let base_str = base_dir.to_string_lossy();
    if !result_str.starts_with(base_str.as_ref()) {
        return Err(UnixtractError::UnsafePath {
            path: PathBuf::from(firmware_path),
        });
    }

    Ok(result)
}
