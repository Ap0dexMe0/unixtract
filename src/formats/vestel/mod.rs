mod include;
use std::any::Any;
use crate::AppContext;

use std::fs::{self, OpenOptions};
use std::io::Write;

use crate::utils::common;
use crate::keys;
use crate::utils::aes::{decrypt_aes128_ecb};
use include::*;

pub fn is_vestel_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    let file_size = file.metadata()?.len() as usize;

    let header = common::read_file(&file, 0, 32)?;
    if header.windows(6).any(|w| w == b"VESTEL") {
        return Ok(Some(Box::new(VestelCtx { is_encrypted: false })));
    }

    let vestel_key = keys::VESTEL.first();
    if vestel_key.is_none() {
        return Ok(None);
    }
    let (_key_name, key_hex) = vestel_key.unwrap();

    let key = hex::decode(key_hex)?;
    if key.len() != 16 {
        return Ok(None);
    }
    let key_bytes: [u8; 16] = key.try_into().map_err(|_| "Invalid key length")?;

    if file_size % 16 != 0 {
        return Ok(None);
    }

    let data = common::read_exact(&mut file.try_clone()?, file_size)?;
    let decrypted = decrypt_aes128_ecb(&key_bytes, &data)?;

    if decrypted.windows(6).any(|w| w == b"VESTEL") {
        Ok(Some(Box::new(VestelCtx { is_encrypted: true })))
    } else {
        Ok(None)
    }
}

pub fn extract_vestel(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<VestelCtx>().expect("Missing context");

    let file_size = file.metadata()?.len() as usize;
    let data = common::read_exact(&mut file, file_size)?;

    let (key_name, key_hex) = keys::VESTEL.first()
        .ok_or("VESTEL key not found!")?;

    let key = hex::decode(key_hex)?;
    let key_len = key.len();
    let key_bytes = match key.try_into() {
        Ok(bytes) => bytes,
        Err(_) => return Err(format!("Invalid VESTEL key length: expected 16 bytes, got {}", key_len).into()),
    };

    let (decrypted_data, decrypted_path) = if ctx.is_encrypted {
        println!("Detected encrypted Vestel firmware, using key: {} ({})", key_name, key_hex);
        println!("Decrypting firmware...");
        let dec_data = decrypt_aes128_ecb(&key_bytes, &data)?;

        let output_path = std::path::Path::new(&app_ctx.output_dir).join("_decrypted.bin");
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).truncate(true).open(&output_path)?;
        out_file.write_all(&dec_data)?;
        (dec_data, Some(output_path))
    } else {
        println!("Detected Vestel firmware (unencrypted)");
        (data, None)
    };

    let partitions = VESTEL_PARTITIONS;
    println!("\nPartition count: {}", partitions.len());

    for (name, (offset, size)) in partitions.iter() {
        let end = offset + size;
        if end > decrypted_data.len() {
            println!("\nWarning: Partition {} extends beyond firmware bounds (offset=0x{:X}, size=0x{:X})", name, offset, size);
        }

        let segment = &decrypted_data[*offset..std::cmp::min(end, decrypted_data.len())];

        println!("\n{} - Offset: 0x{:X}, Size: 0x{:X}", name, offset, size);

        let output_path = std::path::Path::new(&app_ctx.output_dir).join(format!("{}.bin", name));

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).truncate(true).open(output_path)?;
        out_file.write_all(segment)?;

        println!("- Saved {}.bin", name);
    }

    if let Some(path) = decrypted_path {
        if !app_ctx.has_option("vestel:keep_decrypted") {
            fs::remove_file(&path)?;
        }
    }

    Ok(())
}
