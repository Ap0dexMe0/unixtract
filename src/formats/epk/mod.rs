use std::any::Any;
use std::io::Seek;
use crate::AppContext;

use crate::utils::common;
use crate::utils::aes::decrypt_aes_ecb_auto;
use crate::formats;
use log::info;

pub struct EpkContext {
    epk_version: u8,
    versions: Vec<u8>,
}

pub fn is_epk_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let versions = common::read_file(&file, 1712, 36)?;
    if let Some(epk_version) = check_epk_version(&versions) {
        Ok(Some(Box::new(EpkContext {epk_version, versions})))
    } else {
        Ok(None)
    }
}

fn check_epk_version(versions: &[u8]) -> Option<u8> {
    //                      _ - 0x00     X - a number    . - a dot
    let epk2_pattern =              "____XXXX.XXXX.XXXX__XX.XX.XXX_______";
    let epk3_pattern =              "____X.X.X___________X.X.X___________";
    let epk3_another_pattern =      "____X.XX.X__________X.XX.X__________";
    let epk3_new_pattern =          "____XX.X.X__________XX.X.X__________";

    if match_with_pattern(&versions, epk2_pattern) {
        Some(2)
    } else if match_with_pattern(&versions, epk3_pattern) {
        Some(3)
    } else if match_with_pattern(&versions, epk3_another_pattern) {
        Some(3)
    } else if match_with_pattern(&versions, epk3_new_pattern) {
        Some(3)
    } else {
        None
    }
}

fn match_with_pattern(data: &[u8], pattern: &str) -> bool {
    for (&b, p) in data.iter().zip(pattern.bytes()) {
        match p {
            b'_' if b != 0x00           => return false,
            b'X' if !b.is_ascii_digit() => return false,
            b'.' if b != b'.'           => return false,
            _ => {}
        }
    }
    true
}

pub fn extract_epk(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<EpkContext>().map_err(|_| "Invalid context type")?;

    let platform_version = common::string_from_bytes(&ctx.versions[4..20]);
    let sdk_version = common::string_from_bytes(&ctx.versions[20..36]);
    info!("Platform version: {}\nSDK version: {}", platform_version, sdk_version);

    file.seek(std::io::SeekFrom::Start(0))?;

    if ctx.epk_version == 2 {
        info!("EPK2 detected!\n");
        formats::epk2::extract_epk2(app_ctx, Box::new(()))?;
    } else if ctx.epk_version == 3 {
        info!("EPK3 detected!\n");
        formats::epk3::extract_epk3(app_ctx, Box::new(()))?;
    }

    Ok(())
}

// COMMON EPK FUNCTIONS

/// Try each key in `key_array` to find one that decrypts `data` with a header
/// matching `expected_magic`. Returns the key name and the raw key bytes on
/// success, or `None` if no key works.
pub fn find_key<'a>(key_array: &'a [(&'a str, &'a str)], data: &[u8], expected_magic: &[u8]) -> Result<Option<(&'a str, Vec<u8>)>, Box<dyn std::error::Error>> {
    for (key_hex, name) in key_array {
        let key_bytes = hex::decode(key_hex)?;
        let decrypted = match decrypt_aes_ecb_auto(&key_bytes, data) {
            Ok(d) => d,
            Err(_) => continue,
        };

        if decrypted.starts_with(expected_magic) {
            return Ok(Some((name, key_bytes)));
        }
    }
    Ok(None)
}
