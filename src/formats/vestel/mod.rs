mod include;
use std::any::Any;
use crate::AppContext;

use std::fs;
use crate::utils::common;
use crate::utils::aes::decrypt_aes128_ecb;
use crate::keys;

use include::*;

pub fn is_vestel_file(
    app_ctx: &AppContext,
) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let mut file = match app_ctx.file() {
        Some(f) => f,
        None => return Ok(None),
    };

    let file_size = file.metadata()?.len() as usize;

    // 1. FAST PATH: plaintext check
    let header = common::read_file(&file, 0, 64)?;

    if header.windows(5).any(|w| w == b"OPTEE") {
        return Ok(Some(Box::new(VestelCtx {
            is_encrypted: false,
        })));
    }

    // 2. KEY CHECK
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

    // 3. SIZE CHECK
    if file_size < 32 {
        return Ok(None);
    }

    // 4. Read file
    let data = common::read_exact(&mut file, file_size)?;

    // 5. Python equivalent trimming
    let cut_len = data.len().saturating_sub(16) & !0xF;

    if cut_len == 0 {
        return Ok(None);
    }

    // 6. decrypt candidate
    let decrypted = decrypt_aes128_ecb(&key, &data[..cut_len])?;

    // 7. verify OPTEE in decrypted output
    if decrypted.windows(5).any(|w| w == b"OPTEE") {
        return Ok(Some(Box::new(VestelCtx {
            is_encrypted: true,
        })));
    }

    Ok(None)
}

pub fn extract_vestel(
    app_ctx: &AppContext,
    ctx: Box<dyn Any>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<VestelCtx>().expect("Missing context");

    let file_size = file.metadata()?.len() as usize;
    let data = common::read_exact(&mut file, file_size)?;

    let (_, key_hex) = keys::VESTEL
        .first()
        .ok_or("VESTEL key not found!")?;

    let key_vec = hex::decode(key_hex)?;
    let key: [u8; 16] = key_vec.try_into().map_err(|_| "Invalid AES key length")?;

    // decrypt if needed
    let (final_data, decrypted_path) = if ctx.is_encrypted {
        println!("Encrypted Vestel firmware detected");
        println!("Using key: {} ({})", "VESTEL", key_hex);

        let dec = decrypt_aes128_ecb(&key, &data)?;

        let output_path = std::path::Path::new(&app_ctx.output_dir)
            .join("_decrypted.bin");

        fs::create_dir_all(&app_ctx.output_dir)?;
        fs::write(&output_path, &dec)?;

        (dec, Some(output_path))
    } else {
        println!("Detected Vestel firmware (unencrypted)");
        (data, None)
    };

    let partitions = VESTEL_PARTITIONS;
    println!("\nPartition count: {}", partitions.len());

    fs::create_dir_all(&app_ctx.output_dir)?;

    for (name, (offset, size)) in partitions.iter() {
        let start = *offset;
        let end = start.saturating_add(*size);

        if start >= final_data.len() {
            println!("Skipping {} (out of range)", name);
            continue;
        }

        let end = end.min(final_data.len());
        let segment = &final_data[start..end];

        println!(
            "\n{} - Offset: 0x{:X}, Size: 0x{:X}",
            name, offset, size
        );

        let output_path = std::path::Path::new(&app_ctx.output_dir)
            .join(format!("{}.bin", name));

        fs::write(&output_path, segment)?;

        println!("- Saved {}.bin", name);
    }

    // cleanup decrypted temp file if not needed
    if let Some(path) = decrypted_path {
        if !app_ctx.has_option("vestel:keep_decrypted") {
            let _ = fs::remove_file(path);
        }
    }

    Ok(())
}