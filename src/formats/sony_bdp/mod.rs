mod include;
use std::any::Any;
use crate::{InputTarget, AppContext};

use std::fs::File;
use std::path::{Path, PathBuf};
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::formats;
use crate::keys;
use include::*;
use log::{debug, info};

struct SonyBdpCtx {
    encryption_type: EncryptionType,
}

pub fn is_sony_bdp_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    let header_magic = common::read_file(&file, 0, 16)?;
    debug!("sony_bdp: header_magic={:02X?}", header_magic);

    //try old encryption (hex subst)
    if is_valid_header_magic(&hex_substitute(&header_magic)) {
        debug!("sony_bdp: matched HexSubst encryption");
        return Ok(Some(Box::new(
            SonyBdpCtx {encryption_type: 
                EncryptionType::HexSubst
            }
        )));
    }

    //try new encryption (aes)
    for (key_hex, iv_hex, name) in keys::SONY_BDP_AES {
        let key_array: [u8; 16] = hex::decode(key_hex)?.as_slice().try_into()?;
        let iv_array: [u8; 16] = hex::decode(iv_hex)?.as_slice().try_into()?;
        let try_decrypt = ver_up_decrypt_aes128ofb(&key_array, &iv_array, &header_magic);

        if is_valid_header_magic(&try_decrypt) {
            debug!("sony_bdp: matched AES-OFB key '{}'", name);
            return Ok(Some(Box::new(
                SonyBdpCtx {encryption_type: 
                    EncryptionType::AesOfb((key_array, iv_array, name.to_string()))
                }
            )));
        }
    }
    debug!("sony_bdp: no encryption match, skipping");
    Ok(None)
}

pub fn extract_sony_bdp(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<SonyBdpCtx>().map_err(|_| "Invalid context type")?;
    debug!("sony_bdp: encryption_type={:?}", ctx.encryption_type);

    //need to decrypt entire file of new aes enc
    let mut enc_data = Vec::new();
    let enc_size = file.read_to_end(&mut enc_data)?;
    debug!("sony_bdp: read {} encrypted bytes", enc_size);

    let dec_data = match ctx.encryption_type {
        EncryptionType::HexSubst => {
            info!("Decrypting with hex substitution...");
            hex_substitute(&enc_data)
        },
        EncryptionType::AesOfb((key, iv, key_name)) => {
            info!("Decrypting with AES key: {}...", key_name);
            ver_up_decrypt_aes128ofb(&key, &iv, &enc_data)
        }
    };
    debug!("sony_bdp: decrypted to {} bytes", dec_data.len());
    let mut data_reader = Cursor::new(dec_data);

    let header = common::read_exact(&mut data_reader, 300)?;
    let mut hdr_reader = Cursor::new(header);
    let hdr: Header = hdr_reader.read_le()?;
    debug!("sony_bdp: firmware={}, version={}, date={}, file_size={}", hdr.firmware_name(), hdr.firmware_version(), hdr.date(), hdr.file_size);

    info!("File info:\nFirmware: {}\nVersion: {}\nDate: {}\nFile size: {}", 
            hdr.firmware_name(), hdr.firmware_version(), hdr.date(), hdr.file_size);

    let mut last_file_path: Option<PathBuf> = None;
    let mut first_entry_offset = 0;
    let mut i = 0;
    loop {
        
        if (i != 0) && (hdr_reader.position() >= first_entry_offset) {
            break
        }

        let entry: Entry = hdr_reader.read_le()?;
        debug!("sony_bdp: entry[{}] offset={} size={}", i, entry.offset, entry.size);
        if entry.size == 0 {
            continue
        }

        info!("\n#{} - Offset: {}, Size: {}", i, entry.offset, entry.size);
        if i == 0 {
            first_entry_offset = entry.offset as u64;
        }

        data_reader.seek(SeekFrom::Start(entry.offset as u64))?;
        let data = common::read_exact(&mut data_reader, entry.size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", i+1));
        last_file_path = Some(output_path.clone());

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;          
        out_file.write_all(&data)?;

        info!("- Saved file!");
        i += 1;
    }

    //The last file is the host MTK BDP file so we can extract that here (wont work for pre-linux which have old mtk bdp though.)
    if last_file_path.is_some() {
        let last_file = File::open(last_file_path.unwrap())?;
        let mtk_extraction_path = app_ctx.output_dir.join(format!("{}", i));

        let ctx: AppContext = AppContext {
            input: InputTarget::File(last_file),
            output_dir: mtk_extraction_path,
            options: app_ctx.options.clone(),
            dry_run: app_ctx.dry_run,
            quiet: app_ctx.quiet,
            verbose: app_ctx.verbose,
        };

        if let Some(result) = formats::mtk_bdp::is_mtk_bdp_file(&ctx)? {
            info!("- MTK BDP file detected!\n");
            formats::mtk_bdp::extract_mtk_bdp(&ctx, result)?;
        } else {
            info!("- Not an MTK BDP file.");    
        }
    }
     
    Ok(())
}
