//! UBI / UBIFS NAND rootfs extractor.
//!
//! Handles raw UBI images as commonly carved out of MStar/Toshiba NAND dumps
//! (e.g. `rootfs_ubi.bin` produced by the `mstar_unfd` format). These images
//! frequently still carry the NAND spare/OOB bytes interleaved after every
//! page, and use a vendor-quirked UBI layout (EC header `data_offset` field
//! reads 0). This module:
//!
//!   1. Detects the `UBI#` erase-counter header at offset 0.
//!   2. Auto-detects and strips interleaved OOB (page + spare geometry).
//!   3. Parses per-PEB EC/VID headers (big-endian) and rebuilds each logical
//!      volume by ordering LEBs and keeping the copy with the highest sqnum.
//!   4. Reads the UBI volume table (layout volume) to recover volume names.
//!   5. Hands each data volume's reconstructed image to the UBIFS walker
//!      ([`ubifs`]) which rebuilds the file tree.

use std::any::Any;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};

use log::{info, warn};

use crate::AppContext;

pub mod ubifs;

/// UBI erase-counter header magic ("UBI#").
const EC_MAGIC: &[u8; 4] = b"UBI#";
/// UBI volume-identifier header magic ("UBI!").
const VID_MAGIC: &[u8; 4] = b"UBI!";
/// vol_id of the internal layout volume that holds the volume table.
const UBI_LAYOUT_VOLUME_ID: u32 = 0x7FFF_EFFF;
/// Size of a single volume-table record.
const UBI_VTBL_RECORD_SIZE: usize = 172;
/// NAND main page size we assume for OOB detection.
const NAND_PAGE_SIZE: usize = 2048;

/// Geometry / layout information for a UBI image.
#[derive(Debug, Clone)]
pub struct UbiCtx {
    /// Physical erase block size as stored in the file (may include OOB).
    pub phys_peb_size: usize,
    /// OOB/spare bytes interleaved after each `NAND_PAGE_SIZE` page (0 = none).
    pub oob_size: usize,
    /// Clean PEB size after OOB has been removed.
    pub clean_peb_size: usize,
    /// Number of physical erase blocks in the image.
    pub peb_count: usize,
}

/// Detect a UBI image: `UBI#` at offset 0, and derive PEB geometry (including
/// any interleaved NAND OOB) from the spacing of consecutive EC headers.
pub fn is_ubi_file(
    app_ctx: &AppContext,
) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {
        Some(f) => f,
        None => return Ok(None),
    };

    let mut head = [0u8; 4];
    {
        let mut f = file;
        f.seek(SeekFrom::Start(0))?;
        if f.read_exact(&mut head).is_err() {
            return Ok(None);
        }
    }
    if &head != EC_MAGIC {
        return Ok(None);
    }

    let file_size = file.metadata()?.len() as usize;

    // Find the spacing between the first two EC headers to learn the physical
    // PEB size (OOB-interleaved or not). Scan a bounded prefix so detection
    // stays cheap.
    let scan_len = file_size.min(4 * 1024 * 1024);
    let prefix = crate::utils::common::read_file(&file, 0, scan_len)?;
    let phys_peb_size = match second_magic_offset(&prefix, EC_MAGIC) {
        Some(d) if d > 0 => d,
        // Only one EC header visible in the prefix — fall back to a common
        // clean PEB size guess.
        _ => guess_single_peb(file_size),
    };

    let oob_size = detect_oob(phys_peb_size);
    let pages = phys_peb_size / (NAND_PAGE_SIZE + oob_size);
    let clean_peb_size = pages * NAND_PAGE_SIZE;
    let peb_count = file_size / phys_peb_size;

    if clean_peb_size == 0 || peb_count == 0 {
        return Ok(None);
    }

    info!("- Detected UBI image");
    info!(
        "  physical PEB: {} bytes, OOB/page: {} bytes, clean PEB: {} bytes, PEBs: {}",
        phys_peb_size, oob_size, clean_peb_size, peb_count
    );

    Ok(Some(Box::new(UbiCtx {
        phys_peb_size,
        oob_size,
        clean_peb_size,
        peb_count,
    })))
}

/// A reconstructed logical volume: its LEBs concatenated in `lnum` order.
struct Volume {
    /// lnum -> (sqnum, leb data)
    lebs: HashMap<u32, (u64, Vec<u8>)>,
}

pub fn extract_ubi(
    app_ctx: &AppContext,
    ctx: Box<dyn Any>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx.downcast::<UbiCtx>().map_err(|_| "Invalid UBI context")?;

    let input_path = app_ctx
        .input_path()
        .ok_or("UBI extractor requires an input path")?;
    let mut file = File::open(input_path)?;

    fs::create_dir_all(&app_ctx.output_dir)?;

    // --- Parse every physical erase block ---
    let mut volumes: HashMap<u32, Volume> = HashMap::new();
    let mut buf = vec![0u8; ctx.phys_peb_size];

    for peb in 0..ctx.peb_count {
        file.seek(SeekFrom::Start((peb * ctx.phys_peb_size) as u64))?;
        if file.read_exact(&mut buf).is_err() {
            break;
        }

        let clean = strip_oob(&buf, ctx.oob_size, ctx.clean_peb_size);

        if &clean[0..4] != EC_MAGIC {
            continue; // erased / non-UBI block
        }

        // EC header (big-endian). vid_hdr_offset @0x10, data_offset @0x14.
        let mut vid_hdr_offset = be32(&clean, 0x10) as usize;
        let mut data_offset = be32(&clean, 0x14) as usize;

        // Vendor quirk: fields may read 0. Fall back to page-aligned defaults.
        if vid_hdr_offset == 0 || vid_hdr_offset + 64 > ctx.clean_peb_size {
            vid_hdr_offset = NAND_PAGE_SIZE;
        }
        if data_offset == 0 || data_offset >= ctx.clean_peb_size {
            data_offset = vid_hdr_offset + NAND_PAGE_SIZE;
        }

        if vid_hdr_offset + 64 > clean.len() || &clean[vid_hdr_offset..vid_hdr_offset + 4] != VID_MAGIC
        {
            continue; // no valid VID header -> unmapped PEB
        }

        // VID header (big-endian). vol_id @0x08, lnum @0x0C, sqnum @0x28.
        let vol_id = be32(&clean, vid_hdr_offset + 0x08);
        let lnum = be32(&clean, vid_hdr_offset + 0x0C);
        let sqnum = be64(&clean, vid_hdr_offset + 0x28);

        if data_offset >= clean.len() {
            continue;
        }
        let leb_data = clean[data_offset..].to_vec();

        let vol = volumes.entry(vol_id).or_insert_with(|| Volume {
            lebs: HashMap::new(),
        });
        // Keep the newest copy (highest sqnum) of each LEB.
        match vol.lebs.get(&lnum) {
            Some((prev_sq, _)) if *prev_sq >= sqnum => {}
            _ => {
                vol.lebs.insert(lnum, (sqnum, leb_data));
            }
        }
    }

    if volumes.is_empty() {
        warn!("  No valid UBI volumes found");
        return Ok(());
    }

    // --- Recover volume names from the layout volume's volume table ---
    let names = volumes
        .get(&UBI_LAYOUT_VOLUME_ID)
        .map(|v| parse_volume_table(v))
        .unwrap_or_default();

    info!("  Found {} UBI volume(s)", volumes.len());

    // --- Reconstruct and extract each data volume ---
    let mut vol_ids: Vec<u32> = volumes.keys().cloned().collect();
    vol_ids.sort_unstable();

    for vol_id in vol_ids {
        if vol_id == UBI_LAYOUT_VOLUME_ID {
            continue; // internal layout volume, not a filesystem
        }
        let vol = &volumes[&vol_id];

        let name = names
            .get(&vol_id)
            .cloned()
            .unwrap_or_else(|| format!("vol_{vol_id}"));

        let image = reconstruct_volume(vol);
        info!(
            "  Volume '{}' (id {}): {} LEBs, {} bytes",
            name,
            vol_id,
            vol.lebs.len(),
            image.len()
        );

        // Always dump the raw reconstructed volume image alongside the tree.
        let img_path = app_ctx.output_dir.join(format!("{name}.ubifs"));
        if let Err(e) = fs::write(&img_path, &image) {
            warn!("    Could not write {}: {}", img_path.display(), e);
        }

        // Walk the UBIFS filesystem and rebuild files.
        let out_dir = app_ctx.output_dir.join(&name);
        match ubifs::extract_ubifs(&image, &out_dir) {
            Ok(n) => info!("    Extracted {} file(s) from '{}'", n, name),
            Err(e) => warn!("    UBIFS extraction of '{}' failed: {}", name, e),
        }
    }

    Ok(())
}

/// Concatenate a volume's LEBs in ascending `lnum` order.
fn reconstruct_volume(vol: &Volume) -> Vec<u8> {
    let mut lnums: Vec<u32> = vol.lebs.keys().cloned().collect();
    lnums.sort_unstable();
    let mut out = Vec::new();
    for lnum in lnums {
        out.extend_from_slice(&vol.lebs[&lnum].1);
    }
    out
}

/// Parse the UBI volume table (stored in the layout volume) into a
/// `vol_id -> name` map. Each record is `UBI_VTBL_RECORD_SIZE` bytes; the
/// record index equals the volume id.
fn parse_volume_table(layout: &Volume) -> HashMap<u32, String> {
    let mut names = HashMap::new();
    // The layout volume mirrors the table across its LEBs; LEB 0 is enough.
    let Some((_, data)) = layout.lebs.get(&0).or_else(|| layout.lebs.values().next()) else {
        return names;
    };

    let count = data.len() / UBI_VTBL_RECORD_SIZE;
    for idx in 0..count {
        let base = idx * UBI_VTBL_RECORD_SIZE;
        let rec = &data[base..base + UBI_VTBL_RECORD_SIZE];
        let reserved_pebs = be32(rec, 0x00);
        if reserved_pebs == 0 {
            continue; // unused record
        }
        let name_len = be16(rec, 0x0E) as usize;
        if name_len == 0 || name_len > 128 {
            continue;
        }
        let name = String::from_utf8_lossy(&rec[0x10..0x10 + name_len]).to_string();
        if !name.is_empty() {
            names.insert(idx as u32, sanitize_name(&name));
        }
    }
    names
}

/// Remove path separators / control characters from a volume name so it is
/// safe to use as a directory name.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_control() || c == '/' || c == '\\' || c == ':' {
                '_'
            } else {
                c
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Remove interleaved OOB from a physical PEB, returning the clean main data.
fn strip_oob(peb: &[u8], oob_size: usize, clean_peb_size: usize) -> Vec<u8> {
    if oob_size == 0 {
        return peb[..clean_peb_size.min(peb.len())].to_vec();
    }
    let step = NAND_PAGE_SIZE + oob_size;
    let mut out = Vec::with_capacity(clean_peb_size);
    let mut pos = 0;
    while pos + NAND_PAGE_SIZE <= peb.len() && out.len() < clean_peb_size {
        out.extend_from_slice(&peb[pos..pos + NAND_PAGE_SIZE]);
        pos += step;
    }
    out.truncate(clean_peb_size);
    out
}

/// Offset of the second occurrence of `magic` (i.e. the distance from the
/// first), searched only on page-aligned boundaries for speed.
fn second_magic_offset(data: &[u8], magic: &[u8; 4]) -> Option<usize> {
    let mut off = NAND_PAGE_SIZE;
    while off + 4 <= data.len() {
        if &data[off..off + 4] == magic {
            return Some(off);
        }
        off += NAND_PAGE_SIZE;
    }
    None
}

/// Determine the OOB size per page given a physical PEB size. Prefers no OOB;
/// otherwise picks the first spare size that divides the PEB into a power-of-two
/// page count.
fn detect_oob(phys_peb_size: usize) -> usize {
    for oob in [0usize, 16, 32, 64, 128, 218, 224, 256] {
        let step = NAND_PAGE_SIZE + oob;
        if phys_peb_size % step != 0 {
            continue;
        }
        let pages = phys_peb_size / step;
        if pages.is_power_of_two() && (16..=4096).contains(&pages) {
            return oob;
        }
    }
    0
}

/// Fallback PEB size when only one EC header is present.
fn guess_single_peb(file_size: usize) -> usize {
    for peb in [131072usize, 262144, 126976, 524288, 65536] {
        if file_size % peb == 0 {
            return peb;
        }
    }
    131072
}

// --- endian helpers ---------------------------------------------------------

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn be64(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        b[off], b[off + 1], b[off + 2], b[off + 3], b[off + 4], b[off + 5], b[off + 6], b[off + 7],
    ])
}
