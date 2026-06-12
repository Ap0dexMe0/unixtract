use std::any::Any;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use flate2::read::DeflateDecoder;
use log::{debug, info, warn};

use crate::AppContext;
use crate::utils::common;
use crate::utils::path_sanitize::safe_output_path;

const LOCAL_FILE_HEADER_SIZE: u64 = 30;
const CENTRAL_DIRECTORY_HEADER_SIZE: u64 = 46;
const END_OF_CENTRAL_DIRECTORY_SIZE: u64 = 22;
const ZIP_EOCD_SEARCH_LIMIT: u64 = 65_557;

const LOCAL_FILE_HEADER_MAGIC: u32 = 0x0403_4b50;
const CENTRAL_DIRECTORY_HEADER_MAGIC: u32 = 0x0201_4b50;
const END_OF_CENTRAL_DIRECTORY_MAGIC: u32 = 0x0605_4b50;

const COMPRESSION_STORED: u16 = 0;
const COMPRESSION_DEFLATED: u16 = 8;

pub enum AndroidOtaZipContext {
    AndroidOta { updater_script: String },
    GenericZip,
}

#[derive(Clone)]
struct ZipEntry {
    name: String,
    compression_method: u16,
    compressed_size: u64,
    uncompressed_size: u64,
    local_header_offset: u64,
}

#[derive(Clone, Debug)]
enum ScriptAction {
    WholeImage {
        device: String,
        image: String,
    },
    BlockBackup {
        device: String,
        offset: u32,
        blocks: u32,
    },
    BlockRecovery {
        device: String,
        offset: u32,
        blocks: u32,
    },
    PackageExtract {
        image: String,
        destination: String,
    },
}

pub fn is_android_ota_zip_file(
    app_ctx: &AppContext,
) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file_ref = match app_ctx.file() {
        Some(file) => file,
        None => return Ok(None),
    };

    if file_ref.metadata()?.len() < 2 {
        return Ok(None);
    }

    let header = common::read_file(file_ref, 0, 2)?;
    if &header != b"PK" {
        return Ok(None);
    }

    if let Some(input_path) = app_ctx.input_path() {
        if let Some(ext) = input_path.extension().and_then(|e| e.to_str()) {
            if !ext.eq_ignore_ascii_case("zip") {
                info!("Detected ZIP archive with non-ZIP extension (.{}), treating as ZIP", ext);
            }
        }
    }

    let mut file = file_ref.try_clone()?;
    let entries = match read_zip_entries(&mut file) {
        Ok(entries) => entries,
        Err(error) => {
            debug!("File starts with PK magic but is not a valid ZIP: {}", error);
            return Ok(None);
        }
    };

    let Some(script_entry) = entries
        .iter()
        .find(|entry| entry.name == "META-INF/com/tcl/updater-script")
    else {
        return Ok(Some(Box::new(AndroidOtaZipContext::GenericZip)));
    };

    let updater_script = match extract_entry_data(&mut file, script_entry) {
        Ok(data) => String::from_utf8_lossy(&data).to_string(),
        Err(error) => {
            debug!("android_ota_zip: updater script could not be read: {}", error);
            return Ok(Some(Box::new(AndroidOtaZipContext::GenericZip)));
        }
    };

    Ok(Some(Box::new(AndroidOtaZipContext::AndroidOta {
        updater_script,
    })))
}

pub fn extract_android_ota_zip(
    app_ctx: &AppContext,
    ctx: Box<dyn Any>,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_ref = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx
        .downcast::<AndroidOtaZipContext>()
        .map_err(|_| "Invalid context type")?;
    let renamed_zip_path = maybe_rename_input_to_zip(app_ctx)?;
    let mut file = file_ref.try_clone()?;

    fs::create_dir_all(&app_ctx.output_dir)?;

    let entries = read_zip_entries(&mut file)?;

    match *ctx {
        AndroidOtaZipContext::AndroidOta { ref updater_script } => {
            let actions = parse_updater_script(updater_script);

            info!("TCL Android OTA ZIP detected");
            info!("ZIP entries: {}", entries.len());
            info!("Partition actions: {}", actions.len());

            let mut ota_image_names: HashSet<String> = HashSet::new();
            for action in &actions {
                match action {
                    ScriptAction::WholeImage { image, .. }
                    | ScriptAction::PackageExtract { image, .. } => {
                        ota_image_names.insert(image.clone());
                    }
                    ScriptAction::BlockBackup { .. } | ScriptAction::BlockRecovery { .. } => {}
                }
            }

            extract_all_entries_with_progress(
                &mut file,
                &entries,
                &app_ctx.output_dir,
                &ota_image_names,
            )?;

            write_dumper_script(&app_ctx.output_dir, &actions)?;
            write_partition_map(&app_ctx.output_dir, &actions)?;

            if !actions.is_empty() {
                info!("- Generated dump_partitions.sh and partitions.tsv");
            }
        }
        AndroidOtaZipContext::GenericZip => {
            info!("ZIP archive detected");
            info!("ZIP entries: {}", entries.len());
            extract_all_entries_with_progress(
                &mut file,
                &entries,
                &app_ctx.output_dir,
                &HashSet::new(),
            )?;
        }
    }

    if let Some(zip_path) = renamed_zip_path {
        if let Err(e) = fs::remove_file(&zip_path) {
            warn!("Could not remove {}: {}", zip_path.display(), e);
        }
    }

    Ok(())
}

fn maybe_rename_input_to_zip(
    app_ctx: &AppContext,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    let Some(input_path) = app_ctx.input_path() else {
        return Ok(None);
    };

    if let Some(extension) = input_path
        .extension()
        .and_then(|extension| extension.to_str())
    {
        if extension.eq_ignore_ascii_case("zip") {
            return Ok(None);
        }
    }

    let zip_path = input_path.with_extension("zip");
    if zip_path.exists() {
        warn!("Input rename skipped because {} already exists", zip_path.display());
        return Ok(None);
    }

    match fs::rename(input_path, &zip_path) {
        Ok(()) => {
            info!("Renamed input file from {} to {}", input_path.display(), zip_path.display());
            Ok(Some(zip_path))
        }
        Err(e) => {
            warn!("Could not rename {} to {}: {}. Extraction will proceed without renaming.",
                input_path.display(), zip_path.display(), e);
            Ok(None)
        }
    }
}

fn extract_all_entries_with_progress(
    file: &mut File,
    entries: &[ZipEntry],
    output_dir: &Path,
    ota_image_names: &HashSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_entries: Vec<&ZipEntry> = entries
        .iter()
        .filter(|entry| !entry.name.ends_with('/') && !entry.name.ends_with('\\'))
        .collect();
    let total = file_entries.len();

    for (i, entry) in file_entries.iter().enumerate() {
        let output_path = safe_output_path(output_dir, &entry.name)?;

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let compression_label = match entry.compression_method {
            COMPRESSION_DEFLATED => " [DEFLATED]",
            COMPRESSION_STORED => "",
            _ => " [COMPRESSED]",
        };

        let ota_label = if ota_image_names.contains(&entry.name) { " [OTA]" } else { "" };

        info!("\n({}/{}) - {}, Size: {}{}{}",
            i + 1, total, entry.name, entry.uncompressed_size, compression_label, ota_label);

        if entry.compression_method == COMPRESSION_DEFLATED {
            info!("- Decompressing...");
        }

        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&output_path)?;
        extract_entry_to_writer(file, entry, &mut out_file)?;

        info!("-- Saved file!");
    }

    for entry in entries {
        if entry.name.ends_with('/') || entry.name.ends_with('\\') {
            let output_path = safe_output_path(output_dir, &entry.name)?;
            fs::create_dir_all(&output_path)?;
        }
    }

    Ok(())
}

fn read_zip_entries(file: &mut File) -> Result<Vec<ZipEntry>, Box<dyn std::error::Error>> {
    let file_len = file.metadata()?.len();
    if file_len < END_OF_CENTRAL_DIRECTORY_SIZE {
        return Err("ZIP file is too small".into());
    }

    let search_start = file_len.saturating_sub(ZIP_EOCD_SEARCH_LIMIT);
    let search_end = file_len - END_OF_CENTRAL_DIRECTORY_SIZE;

    for pos in (search_start..=search_end).rev() {
        file.seek(SeekFrom::Start(pos))?;
        let mut eocd = [0u8; END_OF_CENTRAL_DIRECTORY_SIZE as usize];
        file.read_exact(&mut eocd)?;

        if read_u32(&eocd, 0) != END_OF_CENTRAL_DIRECTORY_MAGIC {
            continue;
        }

        let total_entries = read_u16(&eocd, 10) as u64;
        let central_dir_size = read_u32(&eocd, 12) as u64;
        let central_dir_offset = read_u32(&eocd, 16) as u64;
        let central_dir_end = central_dir_offset
            .checked_add(central_dir_size)
            .ok_or("ZIP central directory offset overflow")?;

        if central_dir_end > pos || central_dir_end > file_len {
            continue;
        }

        file.seek(SeekFrom::Start(central_dir_offset))?;
        let mut entries = Vec::with_capacity(total_entries as usize);

        for _ in 0..total_entries {
            let mut header = [0u8; CENTRAL_DIRECTORY_HEADER_SIZE as usize];
            file.read_exact(&mut header)?;

            if read_u32(&header, 0) != CENTRAL_DIRECTORY_HEADER_MAGIC {
                return Err("Invalid ZIP central directory entry".into());
            }

            let name_len = read_u16(&header, 28) as u64;
            let extra_len = read_u16(&header, 30) as u64;
            let comment_len = read_u16(&header, 32) as u64;
            let mut name = vec![0u8; name_len as usize];
            file.read_exact(&mut name)?;

            let mut extra = vec![0u8; extra_len as usize];
            file.read_exact(&mut extra)?;

            let mut comment = vec![0u8; comment_len as usize];
            file.read_exact(&mut comment)?;

            entries.push(ZipEntry {
                name: String::from_utf8_lossy(&name).to_string(),
                compression_method: read_u16(&header, 10),
                compressed_size: read_u32(&header, 20) as u64,
                uncompressed_size: read_u32(&header, 24) as u64,
                local_header_offset: read_u32(&header, 42) as u64,
            });
        }

        return Ok(entries);
    }

    Err("ZIP end of central directory not found".into())
}

fn extract_entry_data(
    file: &mut File,
    entry: &ZipEntry,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = Vec::with_capacity(try_usize(entry.uncompressed_size, &entry.name)?);
    let mut cursor = io::Cursor::new(&mut data);
    extract_entry_to_writer(file, entry, &mut cursor)?;
    Ok(data)
}

fn extract_entry_to_writer<W: Write>(
    file: &mut File,
    entry: &ZipEntry,
    writer: &mut W,
) -> Result<(), Box<dyn std::error::Error>> {
    let local_header = read_local_header(file, entry)?;

    file.seek(SeekFrom::Start(local_header.data_offset))?;

    match entry.compression_method {
        COMPRESSION_STORED => copy_stored_entry(file, entry, writer),
        COMPRESSION_DEFLATED => {
            let mut limited = file.take(entry.compressed_size);
            let mut decoder = DeflateDecoder::new(&mut limited);
            copy_reader_to_writer(&mut decoder, writer)
        }
        method => Err(format!(
            "Unsupported ZIP compression method {} for {}",
            method, entry.name
        )
        .into()),
    }
}

fn read_local_header(
    file: &mut File,
    entry: &ZipEntry,
) -> Result<LocalHeader, Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(entry.local_header_offset))?;

    let mut header = [0u8; LOCAL_FILE_HEADER_SIZE as usize];
    file.read_exact(&mut header)?;

    if read_u32(&header, 0) != LOCAL_FILE_HEADER_MAGIC {
        return Err(format!("Invalid local ZIP header for {}", entry.name).into());
    }

    let name_len = read_u16(&header, 26) as u64;
    let extra_len = read_u16(&header, 28) as u64;
    let data_offset = entry
        .local_header_offset
        .checked_add(LOCAL_FILE_HEADER_SIZE)
        .and_then(|offset| offset.checked_add(name_len))
        .and_then(|offset| offset.checked_add(extra_len))
        .ok_or("ZIP local header offset overflow")?;

    Ok(LocalHeader { data_offset })
}

fn copy_stored_entry<W: Write>(
    file: &mut File,
    entry: &ZipEntry,
    writer: &mut W,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut remaining = entry.compressed_size;
    let mut buffer = [0u8; 64 * 1024];

    while remaining > 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        let read = file.read(&mut buffer[..chunk])?;
        if read == 0 {
            return Err(format!("Unexpected end of ZIP data for {}", entry.name).into());
        }
        writer.write_all(&buffer[..read])?;
        remaining -= read as u64;
    }

    Ok(())
}

fn copy_reader_to_writer<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read])?;
    }

    Ok(())
}

fn parse_updater_script(script: &str) -> Vec<ScriptAction> {
    let mut actions = Vec::new();

    for line in script
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        if let Some(args) = parse_function_args(line, "whole_image_update") {
            if args.len() == 2 {
                if let (Some(device), Some(image)) =
                    (parse_string_arg(&args[0]), parse_string_arg(&args[1]))
                {
                    actions.push(ScriptAction::WholeImage { device, image });
                    continue;
                }
            }
        }

        if let Some(args) = parse_function_args(line, "block_Backup") {
            if args.len() == 3 {
                if let (Some(device), Some(offset), Some(blocks)) = (
                    parse_string_arg(&args[0]),
                    parse_u32_arg(&args[1]),
                    parse_u32_arg(&args[2]),
                ) {
                    actions.push(ScriptAction::BlockBackup {
                        device,
                        offset,
                        blocks,
                    });
                    continue;
                }
            }
        }

        if let Some(args) = parse_function_args(line, "block_Recovery") {
            if args.len() == 3 {
                if let (Some(device), Some(offset), Some(blocks)) = (
                    parse_string_arg(&args[0]),
                    parse_u32_arg(&args[1]),
                    parse_u32_arg(&args[2]),
                ) {
                    actions.push(ScriptAction::BlockRecovery {
                        device,
                        offset,
                        blocks,
                    });
                    continue;
                }
            }
        }

        if let Some(args) = parse_function_args(line, "package_extract_file") {
            if args.len() == 2 {
                if let (Some(image), Some(destination)) =
                    (parse_string_arg(&args[0]), parse_string_arg(&args[1]))
                {
                    actions.push(ScriptAction::PackageExtract { image, destination });
                    continue;
                }
            }
        }
    }

    actions
}

fn parse_function_args(line: &str, name: &str) -> Option<Vec<String>> {
    let prefix = format!("{}(", name);
    let rest = line.strip_prefix(&prefix)?;
    let rest = rest.strip_suffix(");")?.trim();

    if rest.is_empty() {
        return Some(Vec::new());
    }

    Some(split_args(rest))
}

fn split_args(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for ch in input.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' && in_quotes {
            escaped = true;
            continue;
        }

        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }

        if ch == ',' && !in_quotes {
            args.push(current.trim().to_string());
            current.clear();
            continue;
        }

        current.push(ch);
    }

    args.push(current.trim().to_string());
    args
}

fn parse_string_arg(arg: &str) -> Option<String> {
    let trimmed = arg.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        Some(trimmed[1..trimmed.len() - 1].to_string())
    } else {
        None
    }
}

fn parse_u32_arg(arg: &str) -> Option<u32> {
    arg.trim().parse().ok()
}

fn write_dumper_script(
    output_dir: &Path,
    actions: &[ScriptAction],
) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = safe_output_path(output_dir, "dump_partitions.sh")?;
    let mut lines = Vec::new();

    lines.push("#!/system/bin/sh".to_string());
    lines.push("set -eu".to_string());
    lines.push("OUT=\"/sdcard/unixtract_dump\"".to_string());
    lines.push("mkdir -p \"$OUT\"".to_string());
    lines.push(String::new());

    let mut whole_image_count = 0;
    for action in actions {
        match action {
            ScriptAction::WholeImage { device, image } => {
                whole_image_count += 1;
                lines.push(format!(
                    "echo \"Dumping {} to {}\"",
                    shell_single_quote(device),
                    shell_single_quote(image)
                ));
                lines.push(format!(
                    "dd if={} of=\"$OUT/{}\" bs=1M conv=fsync",
                    shell_single_quote(device),
                    shell_single_quote(basename(image))
                ));
                lines.push(String::new());
            }
            ScriptAction::BlockBackup {
                device,
                offset,
                blocks,
            } => {
                lines.push(format!(
                    "# block_Backup {} offset={} blocks={}",
                    device, offset, blocks
                ));
            }
            ScriptAction::BlockRecovery {
                device,
                offset,
                blocks,
            } => {
                lines.push(format!(
                    "# block_Recovery {} offset={} blocks={}",
                    device, offset, blocks
                ));
            }
            ScriptAction::PackageExtract { destination, .. } => {
                lines.push(format!(
                    "# Optional package_extract_file payload: {}",
                    destination
                ));
                lines.push(format!(
                    "if [ -f {} ]; then dd if={} of=\"$OUT/{}\" bs=1M conv=fsync; fi",
                    shell_single_quote(destination),
                    shell_single_quote(destination),
                    shell_single_quote(basename(destination))
                ));
                lines.push(String::new());
            }
        }
    }

    if whole_image_count == 0 {
        lines
            .push("echo \"No whole_image_update partitions found in updater-script.\"".to_string());
    }

    lines.push("sync".to_string());
    lines.push("echo \"Done: $OUT\"".to_string());

    write_text_file(&output_path, &lines.join("\n"))
}

fn write_partition_map(
    output_dir: &Path,
    actions: &[ScriptAction],
) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = safe_output_path(output_dir, "partitions.tsv")?;
    let mut lines = Vec::new();

    lines.push("operation\tdevice\timage\toffset\tblocks".to_string());

    for action in actions {
        match action {
            ScriptAction::WholeImage { device, image } => {
                lines.push(format!("whole_image\t{}\t{}\t\t", device, image));
            }
            ScriptAction::BlockBackup {
                device,
                offset,
                blocks,
            } => {
                lines.push(format!(
                    "block_backup\t{}\t\t{}\t{}",
                    device, offset, blocks
                ));
            }
            ScriptAction::BlockRecovery {
                device,
                offset,
                blocks,
            } => {
                lines.push(format!(
                    "block_recovery\t{}\t\t{}\t{}",
                    device, offset, blocks
                ));
            }
            ScriptAction::PackageExtract { image, destination } => {
                lines.push(format!("package_extract\t\t{}\t\t{}", image, destination));
            }
        }
    }

    write_text_file(&output_path, &lines.join("\n"))
}

fn write_text_file(path: &Path, content: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(content.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn basename(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("dump.img")
}

fn try_usize(value: u64, name: &str) -> Result<usize, Box<dyn std::error::Error>> {
    value
        .try_into()
        .map_err(|_| format!("{} is too large", name).into())
}

fn read_u16(buffer: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buffer[offset], buffer[offset + 1]])
}

fn read_u32(buffer: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ])
}

struct LocalHeader {
    data_offset: u64,
}
