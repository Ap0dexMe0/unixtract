mod include;
use std::any::Any;
use crate::AppContext;

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::io::Write;

use crate::utils::common;
use crate::utils::global::opt_dump_dec_hdr;
use crate::utils::compression::{decompress_lzma, decompress_lz4};
use crate::utils::lzop::{unlzop_to_file};
use crate::utils::sparse::{unsparse_to_file};
use include::*;
use log::{debug, info};

pub fn is_mstar_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 32768)?;
    let header_string = String::from_utf8_lossy(&header);
    if header_string.contains("filepartload"){
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_mstar(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let file = app_ctx.file().ok_or("Extractor expected file")?;
    debug!("mstar: starting extraction, script at 0x0 and fallback at 0x1000");

    let mut script = common::read_file(&file, 0, 32768)?;

    if let Some(pos) = script.iter().position(|x| [0x00, 0xFF].contains(x)) {
        script.truncate(pos);
        debug!("mstar: script truncated at offset {}", pos);
    }

    let mut script_string = String::from_utf8_lossy(&script);
    if script_string.is_empty() {
        //try for hisense
        info!("Failed to get script at 0x0, trying 0x1000...");
        script = common::read_file(&file, 4096, 32768)?;
        debug!("mstar: fallback script read {} bytes at 0x1000", script.len());

        if let Some(pos) = script.iter().position(|x| [0x00, 0xFF].contains(x)) {
            script.truncate(pos);
            debug!("mstar: fallback script truncated at offset {}", pos);
        }

        script_string = String::from_utf8_lossy(&script);

        if script_string.is_empty() {
            debug!("mstar: both script reads empty, failing");
            return Err("Failed to get script".into());
        }
    }
    opt_dump_dec_hdr(app_ctx, &script, "script")?;

    let lines: Vec<&str> = script_string.lines().map(|l| l.trim()).collect();
    debug!("mstar: script has {} non-empty lines", lines.len());

    for (i, line) in lines.iter().enumerate() {
        if line.starts_with("filepartload") {
            debug!("mstar: line[{}] = filepartload: {}", i, line);
            let parts: Vec<&str> = line.split_whitespace().collect();
            let offset = parse_number(parts[3]).unwrap_or(0);
            let size = parse_number(parts[4]).unwrap_or(0);

            //try to get partname from comment
            //let mut partname = if let Some(idx) = line.find('#') {
            //    line[idx + 1..].trim()
            //} else {
            //    "unknown"
            //};
            let mut partname = "unknown";
            let mut compression: CompressionType = CompressionType::None;
            let mut lz4_expect_size = 0;
            let mut j = i + 1;
                
            // get lines after this filepartload, before the next one
            while j < lines.len() && !lines[j].starts_with("filepartload") {
                //get compression method
                if lines[j].starts_with("mscompress7"){
                    if compression == CompressionType::None {
                        compression = CompressionType::Lzma;
                    } else if compression == CompressionType::Lzma {
                        //thank the turks
                        compression = CompressionType::DoubleLzma;
                    }
                }
                if lines[j].starts_with("lz4"){
                    compression = CompressionType::Lz4;
                    let parts: Vec<&str> = lines[j].split_whitespace().collect();
                    lz4_expect_size = parse_number(parts[5]).unwrap_or(0);
                }
                if lines[j].starts_with("mmc unlzo"){
                    compression = CompressionType::Lzo;
                    let parts: Vec<&str> = lines[j].split_whitespace().collect();
                    // get part name from mmc unlzo
                    if partname == "unknown" {
                        partname = parts[4]
                    }
                }
                if lines[j].starts_with("sparse_write"){
                    compression = CompressionType::Sparse; //its not really compression but anyway
                    let parts: Vec<&str> = lines[j].split_whitespace().collect();
                    // get part name from sparse_write
                    if partname == "unknown" {
                        partname = parts[3]
                    }
                }

                // check if its boot partition
                if lines[j].starts_with("mmc write.boot") {
                    if partname == "unknown" {
                        partname = "_mmc_boot"
                    }
                }

                // try to get partname from nand/mmc/ubi writes
                if lines[j].starts_with("mmc write") || lines[j].starts_with("nand write") || lines[j].starts_with("ubi write"){
                    let parts: Vec<&str> = lines[j].split_whitespace().collect();
                    if partname == "unknown" {
                        partname = parts[3]
                    }
                }
   
                j += 1;
            }

            info!("\nPart - Offset: {}, Size: {} --> {}", offset, size, partname);

            let data = common::read_file(&file, offset, size.try_into().map_err(|_| "Size conversion failed")?)?;
            let out_data; 
            let output_path = if partname == "unknown" {
                if app_ctx.has_option("mstar:keep_unknown") {
                    info!("- Warning, unknown destination - saving to _unknown_{}.bin", offset);
                    Path::new(&app_ctx.output_dir).join(format!("_unknown_{}.bin", offset))
                } else {
                    info!("- Warning, unknown destination - skipping...");
                    continue;
                }
            } else {
                Path::new(&app_ctx.output_dir).join(format!("{}.bin", partname))
            };

            if compression == CompressionType::Lzma {
                info!("- Decompressing LZMA...");
                out_data = decompress_lzma(&data)?;
            } else if compression == CompressionType::DoubleLzma {
                info!("- Decompressing LZMA (Pass 1)...");
                let pass_1 = decompress_lzma(&data)?;
                info!("- Decompressing LZMA (Pass 2)...");
                out_data = decompress_lzma(&pass_1)?;
            } else if compression == CompressionType::Lz4 {
                info!("- Decompressing lz4, expected size: {}", lz4_expect_size);
                out_data = decompress_lz4(&data, lz4_expect_size.try_into().unwrap())?;
            } else if compression == CompressionType::Lzo {
                info!("- Decompressing LZO..");
                unlzop_to_file(&data, output_path)?;
                info!("-- Saved file!");
                continue
            } else if compression == CompressionType::Sparse {
                info!("- Unsparsing...");
                unsparse_to_file(&data, output_path)?;
                info!("-- Saved file!");
                continue
            } else {
                out_data = data;
            }

            fs::create_dir_all(&app_ctx.output_dir)?;
            let mut out_file = OpenOptions::new().append(true).create(true).open(output_path)?;
            out_file.write_all(&out_data)?;
            info!("-- Saved file!");
        }
    }

    Ok(())
}
