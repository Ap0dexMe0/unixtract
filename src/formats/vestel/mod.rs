mod include;
use std::any::Any;
use crate::AppContext;

use std::fs;
use crate::utils::common;
use crate::utils::aes::decrypt_aes128_ecb;
use crate::keys;

use include::*;
use log::info;

pub struct VestelCtx {
    pub is_encrypted: bool,
    pub variant: VestelVariant,
}

pub enum VestelVariant {
    Standard,
    Mb230,
}

pub fn is_vestel_file(
    app_ctx: &AppContext,
) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let mut file = match app_ctx.file() {
        Some(f) => f,
        None => return Ok(None),
    };

    let file_size = file.metadata()?.len() as usize;

    let header = common::read_file(&file, 0, 64)?;

    if header.windows(5).any(|w| w == b"OPTEE") {
        return Ok(Some(Box::new(VestelCtx {
            is_encrypted: false,
            variant: VestelVariant::Standard,
        })));
    }

    if header.starts_with(b"\xaa\xaa\x55\x55\x55\x55\xaa\xaa") {
        let magic_str = &header[0x10..0x14];
        if magic_str == b"spi\x00" {
            return Ok(Some(Box::new(VestelCtx {
                is_encrypted: false,
                variant: VestelVariant::Mb230,
            })));
        }
    }

    let (_, key_hex) = match keys::VESTEL.first() {
        Some(k) => k,
        None => return Ok(None),
    };

    let key_vec = hex::decode(key_hex)?;
    if key_vec.len() != 16 {
        return Ok(None);
    }

    let key: [u8; 16] = match key_vec.try_into() {
        Ok(k) => k,
        Err(_) => return Ok(None),
    };

    if file_size < 32 {
        return Ok(None);
    }

    let data = common::read_exact(&mut file, file_size)?;

    let cut_len = data.len().saturating_sub(16) & !0xF;

    if cut_len == 0 {
        return Ok(None);
    }

    let decrypted = decrypt_aes128_ecb(&key, &data[..cut_len])?;

    if decrypted.windows(5).any(|w| w == b"OPTEE") {
        return Ok(Some(Box::new(VestelCtx {
            is_encrypted: true,
            variant: VestelVariant::Standard,
        })));
    }

    Ok(None)
}

pub fn extract_vestel(
    app_ctx: &AppContext,
    ctx: Box<dyn Any>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx.downcast::<VestelCtx>().map_err(|_| "Invalid context type")?;

    match ctx.variant {
        VestelVariant::Mb230 => extract_mb230(app_ctx, &ctx),
        VestelVariant::Standard => extract_standard(app_ctx, &ctx),
    }
}

fn extract_standard(
    app_ctx: &AppContext,
    ctx: &VestelCtx,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let file_size = file.metadata()?.len() as usize;
    let data = common::read_exact(&mut file, file_size)?;

    let (_, key_hex) = keys::VESTEL
        .first()
        .ok_or("VESTEL key not found!")?;

    let key_vec = hex::decode(key_hex)?;
    let key: [u8; 16] = key_vec.try_into().map_err(|_| "Invalid AES key length")?;

    let (final_data, decrypted_path) = if ctx.is_encrypted {
        info!("Encrypted Vestel firmware detected");
        info!("Using key: {} ({})", "VESTEL", key_hex);

        let dec = decrypt_aes128_ecb(&key, &data)?;

        let output_path = std::path::Path::new(&app_ctx.output_dir)
            .join("_decrypted.bin");

        fs::create_dir_all(&app_ctx.output_dir)?;
        fs::write(&output_path, &dec)?;

        (dec, Some(output_path))
    } else {
        info!("Detected Vestel firmware (unencrypted)");
        (data, None)
    };

    let partitions = VESTEL_PARTITIONS;
    info!("\nPartition count: {}", partitions.len());

    fs::create_dir_all(&app_ctx.output_dir)?;

    for (name, (offset, size)) in partitions.iter() {
        let start = *offset;
        let end = start.saturating_add(*size);

        if start >= final_data.len() {
            info!("Skipping {} (out of range)", name);
            continue;
        }

        let end = end.min(final_data.len());
        let segment = &final_data[start..end];

        info!(
            "\n{} - Offset: 0x{:X}, Size: 0x{:X}",
            name, offset, size
        );

        let output_path = std::path::Path::new(&app_ctx.output_dir)
            .join(format!("{}.bin", name));

        fs::write(&output_path, segment)?;

        info!("- Saved {}.bin", name);
    }

    if let Some(path) = decrypted_path {
        if !app_ctx.has_option("vestel:keep_decrypted") {
            let _ = fs::remove_file(path);
        }
    }

    Ok(())
}

fn extract_mb230(
    app_ctx: &AppContext,
    _ctx: &VestelCtx,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let file_size = file.metadata()?.len() as usize;
    let data = common::read_exact(&mut file, file_size)?;

    info!("Detected Vestel MB230 firmware (Novatek NT72673)");
    info!("File size: {} bytes ({:.2} MB)", file_size, file_size as f64 / 1024.0 / 1024.0);

    let partitions = MB230_PARTITIONS;
    info!("\nPartition count: {}", partitions.len());

    fs::create_dir_all(&app_ctx.output_dir)?;

    for (name, (offset, size)) in partitions.iter() {
        let start = *offset;
        let end = start.saturating_add(*size);

        if start >= file_size {
            info!("Skipping {} (out of range)", name);
            continue;
        }

        let end = end.min(file_size);
        let segment = &data[start..end];

        info!(
            "\n{} - Offset: 0x{:X}, Size: 0x{:X} ({} bytes)",
            name, offset, size, segment.len()
        );

        let output_path = std::path::Path::new(&app_ctx.output_dir)
            .join(format!("{}.bin", name));

        fs::write(&output_path, segment)?;

        info!("- Saved {}.bin", name);
    }

    Ok(())
}
