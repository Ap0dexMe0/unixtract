use std::any::Any;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use log::{info, warn};

use crate::AppContext;
use crate::utils::common;

const SECTOR_SIZE: u64 = 512;
const GPT_HEADER_LBA: u64 = 1;
const GPT_HEADER_SIZE: usize = 92;
const MAX_GPT_ENTRIES: usize = 128;
const TABLE_DUMP_SIZE: usize = 0x10000;

#[derive(Debug)]
pub struct GptPartition {
    name: String,
    start_lba: u64,
    end_lba: u64,
}

impl GptPartition {
    fn offset(&self) -> u64 {
        self.start_lba * SECTOR_SIZE
    }

    fn size(&self) -> u64 {
        (self.end_lba - self.start_lba + 1) * SECTOR_SIZE
    }
}

fn sanitize_name(raw: &[u8]) -> String {
    let name = raw
        .chunks(2)
        .take_while(|c| c[0] != 0 || c[1] != 0)
        .map(|c| char::from_u32(u32::from_le_bytes([c[0], c[1], 0, 0])).unwrap_or('?'))
        .collect::<String>();

    if name.trim().is_empty() {
        return String::new();
    }

    name.trim()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect()
}

fn parse_gpt_header(data: &[u8]) -> Option<(u64, u64, u64, u32, u32)> {
    if data.len() < GPT_HEADER_SIZE || &data[0..8] != b"EFI PART" {
        return None;
    }

    let entries_lba = u64::from_le_bytes(data[72..80].try_into().unwrap());
    let num_entries = u32::from_le_bytes(data[80..84].try_into().unwrap());
    let entry_size = u32::from_le_bytes(data[84..88].try_into().unwrap());

    let first_usable = u64::from_le_bytes(data[40..48].try_into().unwrap());
    let last_usable = u64::from_le_bytes(data[48..56].try_into().unwrap());

    Some((entries_lba, first_usable, last_usable, num_entries, entry_size))
}

fn parse_gpt_entries(data: &[u8], entry_count: u32, entry_size: u32, file_size: u64) -> Vec<GptPartition> {
    let mut partitions = Vec::new();
    let esize = entry_size as usize;

    for i in 0..entry_count as usize {
        if i >= MAX_GPT_ENTRIES {
            break;
        }
        let off = i * esize;
        if off + 32 > data.len() {
            break;
        }

        // Check if type GUID is all zeros (unused entry)
        if data[off..off + 16].iter().all(|&b| b == 0) {
            break; // GPT entries are contiguous; stop at first unused
        }

        let start_lba = u64::from_le_bytes(data[off + 32..off + 40].try_into().unwrap());
        let end_lba = u64::from_le_bytes(data[off + 40..off + 48].try_into().unwrap());
        let name_raw = &data[off + 56..off + 128];

        if start_lba == 0 || end_lba == 0 {
            continue;
        }

        let name = sanitize_name(name_raw);
        if name.is_empty() {
            continue;
        }

        let part_end = (end_lba + 1) * SECTOR_SIZE;
        if part_end > file_size {
            warn!(
                "Skipping GPT partition '{}' at LBA {}: extends beyond image (end=0x{:x}, file_size=0x{:x})",
                name, start_lba, part_end, file_size
            );
            continue;
        }

        partitions.push(GptPartition {
            name,
            start_lba,
            end_lba,
        });
    }

    partitions
}

pub fn is_emmc_gpt_file(
    app_ctx: &AppContext,
) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {
        Some(file) => file,
        None => return Ok(None),
    };

    let file_size = file.metadata()?.len();
    if file_size < SECTOR_SIZE * 2 || file_size % SECTOR_SIZE != 0 {
        return Ok(None);
    }

    // Read MBR (first sector)
    let mbr = common::read_file(file, 0, SECTOR_SIZE as usize)?;

    // Check MBR signature 0x55AA
    if mbr[0x1FE] != 0x55 || mbr[0x1FF] != 0xAA {
        return Ok(None);
    }

    // Check for GPT protective MBR entry (type 0xEE)
    let has_protective = (0x1BE..0x1FE).step_by(16).any(|i| mbr[i + 4] == 0xEE);
    if !has_protective {
        return Ok(None);
    }

    // Read GPT header at LBA 1
    let gpt_data = common::read_file(file, SECTOR_SIZE * GPT_HEADER_LBA, GPT_HEADER_SIZE)?;

    if parse_gpt_header(&gpt_data).is_none() {
        return Ok(None);
    }

    // We need the entry_size to parse entries, so re-parse
    let (entries_lba, first_usable, _last_usable, num_entries, entry_size) =
        parse_gpt_header(&gpt_data).unwrap();

    let entries_byte_size = (num_entries as usize)
        .min(MAX_GPT_ENTRIES)
        .saturating_mul(entry_size as usize);

    let entries_data = common::read_file(
        file,
        entries_lba * SECTOR_SIZE,
        entries_byte_size,
    )?;

    let partitions = parse_gpt_entries(&entries_data, num_entries, entry_size, file_size);

    if partitions.is_empty() {
        return Ok(None);
    }

    info!(
        "Detected GPT-partitioned eMMC image: {} partitions (size={}, first_usable_lba={})",
        partitions.len(),
        file_size,
        first_usable,
    );

    Ok(Some(Box::new(partitions)))
}

pub fn extract_emmc_gpt(
    app_ctx: &AppContext,
    ctx: Box<dyn Any>,
) -> Result<(), Box<dyn std::error::Error>> {
    let partitions = ctx
        .downcast::<Vec<GptPartition>>()
        .map_err(|_| "Invalid GPT eMMC context")?;

    fs::create_dir_all(&app_ctx.output_dir)?;

    let mut input = app_ctx.file().ok_or("Extractor expected file")?;

    for partition in &*partitions {
        let safe_name: String = partition
            .name
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
            .collect();

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", safe_name));
        let mut output = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&output_path)?;

        input.seek(SeekFrom::Start(partition.offset()))?;
        let copied = io::copy(&mut input.take(partition.size()), &mut output)?;

        info!(
            "  {}: offset=0x{:x}, size={}, copied={}",
            partition.name,
            partition.offset(),
            partition.size(),
            copied,
        );
    }

    write_partition_map(&app_ctx.output_dir, &partitions)?;
    write_gpt_table(app_ctx.file().ok_or("Extractor expected file")?, &app_ctx.output_dir)?;

    Ok(())
}

fn write_partition_map(
    output_dir: &Path,
    partitions: &[GptPartition],
) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = output_dir.join("partition_map.txt");
    let mut output = File::create(output_path)?;

    writeln!(
        output,
        "name\tstart_lba\tend_lba\toffset\tsize"
    )?;
    for partition in partitions {
        writeln!(
            output,
            "{}\t{}\t{}\t0x{:x}\t{}",
            partition.name,
            partition.start_lba,
            partition.end_lba,
            partition.offset(),
            partition.size(),
        )?;
    }

    Ok(())
}

fn write_gpt_table(
    input: &File,
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let table = common::read_file(input, 0, TABLE_DUMP_SIZE)?;
    let output_path = output_dir.join("partition_table.bin");
    let mut output = File::create(output_path)?;
    output.write_all(&table)?;
    Ok(())
}
