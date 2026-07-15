use std::any::Any;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use log::{info, warn};

use crate::{AppContext, InputTarget};
use crate::utils::common;

/// Magic of the MStar UNFD (Universal Nand Flash Driver) Card Information
/// Structure (CIS) that prefixes a raw NAND dump produced by MStar-based
/// tools (common on Toshiba/Winbond/... SLC NAND used in TVs/STBs).
const CIS_MAGIC: &[u8; 16] = b"MSTARSEMIUNFDCIS";

/// Marker that precedes each firmware "bank" inside the dump (a run of
/// `0x02` bytes followed by `0x10 0x10 0x10 0x10`). Used to locate
/// where the real NAND payload begins and how many boot banks are present.
const BANK_MARKER: &[u8] = b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x10\x10\x10\x10";

#[derive(Debug)]
pub struct UnfdCisCtx {
    /// Raw CIS signature dword right after the magic (e.g. 0x91dc9805).
    pub cis_signature: u32,
    /// NAND vendor string (e.g. "TOSHIBA").
    pub vendor: String,
    /// NAND part number string (e.g. "TH58NVG2S3HTA00").
    pub part_number: String,
    /// Logical page data size in bytes (no OOB included).
    pub page_size: u32,
    /// Spare/OOB size per page in bytes.
    pub spare_size: u32,
    /// Number of pages per erase block.
    pub pages_per_block: u32,
    /// Erase block size in bytes (page_size * pages_per_block).
    pub block_size: u32,
    /// Total number of erase blocks in the dump.
    pub block_count: u32,
    /// Total image size in bytes.
    pub total_size: u64,
    /// Offsets of every `MSTARSEMIUNFDCIS` copy found in the image.
    pub cis_copies: Vec<usize>,
    /// Offsets of every firmware bank marker found in the image.
    pub bank_markers: Vec<usize>,
    /// Offset where the actual NAND payload starts (first bank marker).
    pub data_start: usize,
}

pub fn is_mstar_unfd_file(
    app_ctx: &AppContext,
) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {
        Some(f) => f,
        None => return Ok(None),
    };

    // Only the leading CIS header is needed for detection (keep it cheap).
    let header = common::read_file(&file, 0, 512)?;
    if header.len() < 16 || &header[0..16] != CIS_MAGIC {
        return Ok(None);
    }

    let file_size = file.metadata()?.len();
    let cis_signature = u32::from_le_bytes(header[0x10..0x14].try_into().unwrap());
    let vendor = cstr(&header[0x40..0x50]);
    let part_number = cstr(&header[0x50..0x64]);
    let (page_size, spare_size, pages_per_block, block_size, block_count) =
        derive_geometry(file_size);

    info!(
        "- Detected MStar UNFD NAND dump (CIS signature 0x{:08X})",
        cis_signature
    );
    info!("  Vendor: {}, Part: {}", vendor, part_number);
    info!(
        "  NAND geometry: page={}B, spare={}B, pages/block={}, block={}B, blocks={}, total={}B",
        page_size, spare_size, pages_per_block, block_size, block_count, file_size
    );

    Ok(Some(Box::new(UnfdCisCtx {
        cis_signature,
        vendor,
        part_number,
        page_size,
        spare_size,
        pages_per_block,
        block_size,
        block_count,
        total_size: file_size,
        cis_copies: Vec::new(),
        bank_markers: Vec::new(),
        data_start: 0,
    })))
}

pub fn extract_mstar_unfd(
    app_ctx: &AppContext,
    ctx: Box<dyn Any>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = ctx
        .downcast::<UnfdCisCtx>()
        .map_err(|_| "Invalid MStar UNFD context")?;

    fs::create_dir_all(&app_ctx.output_dir)?;

    let input_path = app_ctx
        .input_path()
        .ok_or("MStar UNFD extractor requires an input path")?;
    let mut file = File::open(input_path)?;

    // --- Locate CIS copies and firmware bank markers (full scan) ---
    ctx.cis_copies = scan_offsets(&mut file, CIS_MAGIC)?;
    ctx.bank_markers = scan_offsets(&mut file, BANK_MARKER)?;
    ctx.data_start = *ctx.bank_markers.first().unwrap_or(&0);

    info!(
        "  CIS copies: {:?}",
        ctx.cis_copies
            .iter()
            .map(|o| format!("0x{o:X}"))
            .collect::<Vec<_>>()
    );
    info!(
        "  Bank markers: {:?}",
        ctx.bank_markers
            .iter()
            .map(|o| format!("0x{o:X}"))
            .collect::<Vec<_>>()
    );
    info!("  NAND payload starts at 0x{:X}", ctx.data_start);

    // --- Locate the UBI/rootfs region (first UBI EC header) ---
    let ubi_start = scan_offsets(&mut file, b"UBI#")?
        .into_iter()
        .next()
        .unwrap_or(ctx.total_size as usize);

    // Boot banks are the markers that sit *before* the UBI region.
    let mut boot_markers: Vec<usize> = ctx
        .bank_markers
        .iter()
        .cloned()
        .filter(|&m| m < ubi_start)
        .collect();
    boot_markers.sort_unstable();
    boot_markers.dedup();
    info!("  Boot banks before UBI: {}", boot_markers.len());

    // --- Write a human readable CIS info file ---
    write_cis_info(&app_ctx.output_dir, &ctx, &boot_markers, ubi_start)?;

    // --- Carve each boot bank (marker -> next marker, or UBI start) ---
    let mut carved_names = Vec::new();
    for (i, &start) in boot_markers.iter().enumerate() {
        let end = if i + 1 < boot_markers.len() {
            boot_markers[i + 1]
        } else {
            ubi_start
        };
        if end <= start {
            continue;
        }
        carve_region(
            &mut file,
            &app_ctx.output_dir,
            &format!("boot_bank{i}"),
            start,
            end - start,
        )?;
        carved_names.push(format!("boot_bank{i}"));
    }

    // --- Carve the UBI/rootfs region (if present) ---
    if ubi_start < ctx.total_size as usize {
        carve_region(
            &mut file,
            &app_ctx.output_dir,
            "rootfs_ubi",
            ubi_start,
            ctx.total_size as usize - ubi_start,
        )?;
        carved_names.push("rootfs_ubi".to_string());
    }

    // --- Carve the raw NAND payload (everything after the CIS header) ---
    let payload_len = ctx.total_size.saturating_sub(ctx.data_start as u64);
    if payload_len > 0 {
        file.seek(SeekFrom::Start(ctx.data_start as u64))?;
        let out_path = Path::new(&app_ctx.output_dir).join("nand_data.bin");
        let mut out = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&out_path)?;
        let copied = io::copy(&mut file.take(payload_len), &mut out)?;
        info!(
            "  Carved raw NAND payload -> nand_data.bin ({} bytes, 0x{:X}..0x{:X})",
            copied,
            ctx.data_start,
            ctx.data_start as u64 + copied
        );

        // --- Recursively extract any inner format from the carved payload ---
        recurse_extract(&out_path, app_ctx)?;
    } else {
        warn!("  No NAND payload found after CIS header, skipping carve.");
    }

    // --- Recurse on the carved boot banks as well ---
    for name in &carved_names {
        let p = Path::new(&app_ctx.output_dir).join(format!("{name}.bin"));
        if p.exists() {
            if let Err(e) = recurse_extract(&p, app_ctx) {
                warn!("  Recursion on {name} failed: {e}");
            }
        }
    }

    Ok(())
}

/// Tries every registered format against the carved `path` and extracts
/// each one that matches. The `mstar` format is intentionally skipped:
/// this raw dump's boot script ships as U-Boot `filepartload` format
/// strings (filled at runtime), so `mstar` would only produce empty
/// stubs. Errors from individual formats are caught so one failure does not
/// abort the rest.
fn recurse_extract(
    payload_path: &Path,
    parent_ctx: &AppContext,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(payload_path)?;
    let sub_dir = parent_ctx.output_dir.join("nand_data_extracted");
    fs::create_dir_all(&sub_dir)?;

    let in_ctx: AppContext = AppContext {
        input: InputTarget::File(file),
        input_path: Some(payload_path.to_path_buf()),
        output_dir: sub_dir,
        options: parent_ctx.options.clone(),
        dry_run: parent_ctx.dry_run,
        lazy_run: parent_ctx.lazy_run,
        build_prop: parent_ctx.build_prop,
        dump_keys: parent_ctx.dump_keys,
        quiet: parent_ctx.quiet,
        verbose: parent_ctx.verbose,
    };

    info!("  Scanning carved NAND payload for inner formats...");
    for format in crate::formats::get_registry() {
        if format.name == "mstar" {
            continue;
        }
        match (format.detector_func)(&in_ctx) {
            Ok(Some(ctx)) => {
                info!("  - inner format detected: {}", format.name);
                if let Err(e) = (format.extractor_func)(&in_ctx, ctx) {
                    warn!("    inner extraction ({}) failed: {}", format.name, e);
                }
            }
            Ok(None) => {}
            Err(e) => {
                warn!("    inner detection ({}) error: {}", format.name, e);
            }
        }
    }

    Ok(())
}

/// Derive the NAND geometry purely from the image size. The image is an
/// exact multiple of the page size (no OOB interleaved), which lets us pick
/// a sensible page/block layout even when the CIS body is not fully decoded.
fn derive_geometry(total: u64) -> (u32, u32, u32, u32, u32) {
    let page: u32 = 2048;
    let spare: u32 = if total % (page as u64) != 0 { 64 } else { 0 };

    let mut ppb: u32 = 64;
    for candidate in [64u32, 128, 32, 256, 512] {
        if (total as u64) % ((page as u64) * (candidate as u64)) == 0 {
            ppb = candidate;
            break;
        }
    }

    let block = page * ppb;
    let blocks = (total / (block as u64)) as u32;
    (page, spare, ppb, block, blocks)
}

/// Returns the offsets of every occurrence of `pattern` within `file`,
/// scanning sequentially in buffered chunks. A small overlap (`keep` bytes
/// from the previous chunk) is carried so a match spanning a chunk
/// boundary is still found; the absolute offset is reconstructed from the
/// known file position of the overlap (`hay_base`).
fn scan_offsets(
    file: &mut File,
    pattern: &[u8],
) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
    if pattern.is_empty() {
        return Ok(Vec::new());
    }

    file.seek(SeekFrom::Start(0))?;

    let mut offsets = Vec::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut tail: Vec<u8> = Vec::new();
    let keep = pattern.len() - 1;
    let mut base: usize = 0; // file offset of the current chunk's buffer region

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }

        let hay_base = base.saturating_sub(keep);
        let mut hay = tail;
        hay.extend_from_slice(&buf[..n]);

        let mut start = 0;
        while let Some(rel) = find_sub(&hay[start..], pattern) {
            let idx = start + rel;
            offsets.push(hay_base + idx);
            start = idx + pattern.len();
        }

        tail = hay.split_off(hay.len().saturating_sub(keep));
        base += n;
    }

    Ok(offsets)
}

/// Naive substring search returning the first relative offset of `needle`.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Carves `[start, start+len)` of `file` into `<name>.bin` in `output_dir`.
fn carve_region(
    file: &mut File,
    output_dir: &Path,
    name: &str,
    start: usize,
    len: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if len == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::Start(start as u64))?;
    let out_path = output_dir.join(format!("{name}.bin"));
    let mut out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&out_path)?;
    let copied = io::copy(&mut file.take(len as u64), &mut out)?;
    info!(
        "  Carved {} -> {name}.bin ({} bytes, 0x{:X}..0x{:X})",
        name,
        copied,
        start,
        start as u64 + copied
    );
    Ok(())
}

fn write_cis_info(
    output_dir: &Path,
    ctx: &UnfdCisCtx,
    boot_markers: &[usize],
    ubi_start: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = output_dir.join("cis_info.txt");
    let mut f = File::create(path)?;

    writeln!(f, "MStar UNFD NAND dump - CIS information")?;
    writeln!(f, "=========================================")?;
    writeln!(f, "magic:          MSTARSEMIUNFDCIS")?;
    writeln!(f, "cis_signature:  0x{:08X}", ctx.cis_signature)?;
    writeln!(f, "vendor:         {}", ctx.vendor)?;
    writeln!(f, "part_number:    {}", ctx.part_number)?;
    writeln!(f)?;
    writeln!(f, "Derived NAND geometry:")?;
    writeln!(f, "  page_size:       {} bytes", ctx.page_size)?;
    writeln!(f, "  spare_size:       {} bytes", ctx.spare_size)?;
    writeln!(f, "  pages_per_block:  {}", ctx.pages_per_block)?;
    writeln!(f, "  block_size:       {} bytes", ctx.block_size)?;
    writeln!(f, "  block_count:      {}", ctx.block_count)?;
    writeln!(f, "  total_size:       {} bytes", ctx.total_size)?;
    writeln!(f)?;
    writeln!(
        f,
        "cis_copies:    {:?}",
        ctx.cis_copies
            .iter()
            .map(|o| format!("0x{o:X}"))
            .collect::<Vec<_>>()
    )?;
    writeln!(
        f,
        "bank_markers:   {:?}",
        ctx.bank_markers
            .iter()
            .map(|o| format!("0x{o:X}"))
            .collect::<Vec<_>>()
    )?;
    writeln!(f, "ubi_start:      0x{:X}", ubi_start)?;
    writeln!(f, "data_start:     0x{:X}", ctx.data_start)?;
    writeln!(f)?;
    writeln!(f, "Carved partitions:")?;
    for (i, &m) in boot_markers.iter().enumerate() {
        let end = if i + 1 < boot_markers.len() {
            boot_markers[i + 1]
        } else {
            ubi_start
        };
        writeln!(
            f,
            "  boot_bank{i}: 0x{:X}..0x{:X} ({} bytes)",
            m,
            end,
            end.saturating_sub(m)
        )?;
    }
    if ubi_start < ctx.total_size as usize {
        writeln!(
            f,
            "  rootfs_ubi: 0x{:X}..0x{:X} ({} bytes)",
            ubi_start,
            ctx.total_size,
            ctx.total_size as usize - ubi_start
        )?;
    }
    writeln!(f)?;
    writeln!(
        f,
        "The raw NAND payload (after the CIS header) was carved to nand_data.bin"
    )?;
    writeln!(
        f,
        "and any inner firmware formats were extracted to nand_data_extracted/."
    )?;

    Ok(())
}

/// Decode a NUL-terminated, space-padded ASCII field.
fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).trim().to_string()
}
