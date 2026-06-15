use std::any::Any;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use log::{info, warn};

use crate::AppContext;
use crate::utils::common;

const TABLE_SCAN_BYTES: usize = 0x10000;
const ENTRY_SIZE: usize = 0x200;
const ENTRY_START: usize = 0x200;
const SECTOR_SIZE: u64 = 512;
const MAGIC: &[u8; 8] = b"\x40\x58\x00\x00\x00\x00\x00\x00";

#[derive(Debug)]
pub struct Partition {
    pub name: String,
    pub start_sector: u32,
    pub length_sector: u32,
    pub table_offset: usize,
}

impl Partition {
    fn offset(&self) -> u64 {
        u64::from(self.start_sector) * SECTOR_SIZE
    }

    fn size(&self) -> u64 {
        u64::from(self.length_sector) * SECTOR_SIZE
    }
}

pub fn is_emmc_userarea_file(
    app_ctx: &AppContext,
) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {
        Some(file) => file,
        None => return Ok(None),
    };

    let file_size = file.metadata()?.len();
    if file_size < TABLE_SCAN_BYTES as u64 || file_size % SECTOR_SIZE != 0 {
        return Ok(None);
    }

    let table = common::read_file(file, 0, TABLE_SCAN_BYTES)?;
    let entries = parse_partitions(&table, file_size);

    if entries.is_empty() {
        return Ok(None);
    }

    info!(
        "- Detected raw eMMC user area: {} partitions in first {} bytes",
        entries.len(),
        TABLE_SCAN_BYTES
    );
    Ok(Some(Box::new(entries)))
}

pub fn extract_emmc_userarea(
    app_ctx: &AppContext,
    ctx: Box<dyn Any>,
) -> Result<(), Box<dyn std::error::Error>> {
    let partitions = ctx
        .downcast::<Vec<Partition>>()
        .map_err(|_| "Invalid eMMC user area context")?;

    fs::create_dir_all(&app_ctx.output_dir)?;

    let mut input = app_ctx.file().ok_or("Extractor expected file")?;

    for partition in &*partitions {
        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", partition.name));
        let mut output = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&output_path)?;

        input.seek(SeekFrom::Start(partition.offset()))?;
        let copied = io::copy(&mut input.take(partition.size()), &mut output)?;

        info!(
            "  {}: table_offset=0x{:x}, start_sector=0x{:x}, length_sector=0x{:x}, offset=0x{:x}, size={} bytes, copied={} bytes",
            partition.name,
            partition.table_offset,
            partition.start_sector,
            partition.length_sector,
            partition.offset(),
            partition.size(),
            copied
        );
    }

    write_partition_map(&app_ctx.output_dir, &partitions)?;
    write_partition_table(app_ctx.file().ok_or("Extractor expected file")?, &app_ctx.output_dir)?;

    Ok(())
}

fn parse_partitions(table: &[u8], file_size: u64) -> Vec<Partition> {
    let mut partitions = Vec::new();

    for offset in (ENTRY_START..=table.len().saturating_sub(ENTRY_SIZE)).step_by(ENTRY_SIZE) {
        if &table[offset..offset + 8] != MAGIC {
            continue;
        }

        let start_sector = u32::from_le_bytes(table[offset + 8..offset + 12].try_into().unwrap());
        let length_sector = u32::from_le_bytes(table[offset + 12..offset + 16].try_into().unwrap());
        let name = decode_name(&table[offset + 16..offset + 32]);

        if start_sector == 0 || length_sector == 0 || name.is_empty() {
            continue;
        }

        let Some(partition_offset) = u64::from(start_sector).checked_mul(SECTOR_SIZE) else {
            continue;
        };
        let Some(partition_size) = u64::from(length_sector).checked_mul(SECTOR_SIZE) else {
            continue;
        };
        let Some(partition_end) = partition_offset.checked_add(partition_size) else {
            continue;
        };

        if partition_end > file_size {
            warn!(
                "Skipping eMMC partition {} at 0x{:x}: extends beyond image",
                name, partition_offset
            );
            continue;
        }

        partitions.push(Partition {
            name,
            start_sector,
            length_sector,
            table_offset: offset,
        });
    }

    partitions
}

fn decode_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    raw[..end]
        .iter()
        .filter(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        .map(|byte| *byte as char)
        .collect()
}

fn write_partition_map(
    output_dir: &Path,
    partitions: &[Partition],
) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = output_dir.join("partition_map.txt");
    let mut output = File::create(output_path)?;

    writeln!(
        output,
        "name\ttable_offset\tstart_sector\tlength_sector\toffset\tsize"
    )?;
    for partition in partitions {
        writeln!(
            output,
            "{}\t0x{:x}\t0x{:x}\t0x{:x}\t0x{:x}\t{}",
            partition.name,
            partition.table_offset,
            partition.start_sector,
            partition.length_sector,
            partition.offset(),
            partition.size()
        )?;
    }

    Ok(())
}

fn write_partition_table(
    input: &File,
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let table = common::read_file(input, 0, TABLE_SCAN_BYTES)?;
    let output_path = output_dir.join("partition_table.bin");
    let mut output = File::create(output_path)?;
    output.write_all(&table)?;
    Ok(())
}
