use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::Write;

use crate::utils::common;
use crate::utils::aes::decrypt_aes_ecb_auto;
use crate::keys;

const NVT_PARTITIONS: [(&str, u32, u32); 16] = [
    ("spi_boot", 0x0000020, 0x00020000),
    ("nand_xbootdat", 0x000a0020, 0x0001800),
    ("nand_secos", 0x000c0020, 0x000f5800),
    ("nand_uboot", 0x001c0020, 0x00082800),
    ("nand_fdt0", 0x00260020, 0x0004000),
    ("nand_fdt1", 0x00280020, 0x0004000),
    ("nand_ker0", 0x002a0020, 0x00353000),
    ("nand_ker1", 0x00600020, 0x00db9000),
    ("nand_fs0", 0x013c0020, 0x00f40000),
    ("nand_ap0", 0x02320020, 0x09400000),
    ("nand_apdat0", 0x0b740020, 0x00440000),
    ("nand_buffer", 0x11be0020, 0x003c0000),
    ("nand_logo", 0x05f80020, 0x0060000),
    ("spi_env", 0x0000000, 0x0000000),
    ("nand_ddrcfg", 0x0000000, 0x0000000),
    ("nand_xboot", 0x0000000, 0x0000000),
];

pub fn is_novatek_raw_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    
    let file_size = file.metadata()?.len();
    
    if file_size < 0x10000 {
        return Ok(None);
    }
    
    if app_ctx.has_option("nvt_raw:key") {
        return Ok(Some(Box::new(())));
    }
    
    for _ in keys::NOVATEK_RAW {
        return Ok(Some(Box::new(())));
    }
    
    Ok(None)
}

pub fn extract_novatek_raw(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    
    let key_hex = app_ctx.options.iter()
        .find(|o| o.starts_with("nvt_raw:key="))
        .map(|o| o.strip_prefix("nvt_raw:key=").unwrap())
        .or(keys::NOVATEK_RAW.first().map(|(_, k)| *k));
    
    let key_hex = match key_hex {
        Some(k) => k,
        None => return Err("nvt_raw:key=<hex_key> option required for decryption".into()),
    };
    
    let key = hex::decode(key_hex).map_err(|e| format!("Invalid hex key: {}", e))?;
    
    let file_size = file.metadata()?.len() as usize;
    let enc_data = common::read_file(&mut file, 0, file_size)?;
    
    println!("- File size: {} bytes", file_size);
    println!("- Decrypting with AES-{}...", if key.len() == 16 { "128" } else { "256" });
    
    let dec_data = decrypt_aes_ecb_auto(&key, &enc_data)?;
    
    println!("- Decryption complete");
    
    fs::create_dir_all(&app_ctx.output_dir)?;
    
    let output_path = Path::new(&app_ctx.output_dir).join("_decrypted.bin");
    let mut out_file = OpenOptions::new().write(true).create(true).open(&output_path)?;
    out_file.write_all(&dec_data)?;
    println!("- Saved decrypted image to {}", output_path.display());
    
    println!("\nExtracting partitions:");
    for (name, offset, size) in NVT_PARTITIONS {
        if (offset + size) as usize <= dec_data.len() && size > 0 {
            let part_data = &dec_data[offset as usize..(offset + size) as usize];
            let part_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", name));
            let mut part_file = OpenOptions::new().write(true).create(true).open(&part_path)?;
            part_file.write_all(part_data)?;
            println!("  {}: offset=0x{:x}, size={}", name, offset, size);
        }
    }
    
    Ok(())
}