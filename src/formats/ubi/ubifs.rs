//! Minimal UBIFS reader.
//!
//! Rather than walking the on-flash B-tree index (which vendor images often
//! corrupt or lay out non-standardly), this performs a tolerant *linear* scan
//! of every UBIFS node in a reconstructed volume image. It collects inode,
//! directory-entry and data nodes, validates each with its CRC-32, then
//! rebuilds the directory tree and writes out regular files, directories and
//! symlinks.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};

use flate2::Crc;

/// UBIFS common node header magic (little-endian on disk: 31 18 10 06).
const UBIFS_NODE_MAGIC: u32 = 0x0610_1831;

// Node types.
const INO_NODE: u8 = 0;
const DATA_NODE: u8 = 1;
const DENT_NODE: u8 = 2;

// Header / node sizes.
const CH_SZ: usize = 24; // common header
const DATA_NODE_SZ: usize = 48; // header + key + size + compr fields
const KEY_OFF: usize = 24;

// UBIFS logical data block size (uncompressed).
const UBIFS_BLOCK_SIZE: u64 = 4096;

// Compression types.
const COMPR_NONE: u16 = 0;
const COMPR_LZO: u16 = 1;
const COMPR_ZLIB: u16 = 2;
const COMPR_ZSTD: u16 = 3;

// Inode item types stored in directory entries.
const ITYPE_REG: u8 = 0;
const ITYPE_DIR: u8 = 1;
const ITYPE_LNK: u8 = 2;

/// Root inode number in UBIFS.
const ROOT_INO: u32 = 1;

struct Inode {
    size: u64,
    /// Inline data (symlink target for links).
    inline: Vec<u8>,
}

struct Dent {
    parent: u32,
    target: u32,
    itype: u8,
    name: String,
}

/// Extract a reconstructed UBIFS volume image into `out_dir`. Returns the
/// number of filesystem objects created.
pub fn extract_ubifs(image: &[u8], out_dir: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    let mut inodes: HashMap<u32, Inode> = HashMap::new();
    let mut dents: Vec<Dent> = Vec::new();
    // inode -> block_no -> decompressed bytes
    let mut data: HashMap<u32, HashMap<u64, Vec<u8>>> = HashMap::new();

    scan_nodes(image, &mut inodes, &mut dents, &mut data);

    if inodes.is_empty() && dents.is_empty() {
        return Err("no UBIFS nodes found".into());
    }

    // Build parent -> children map.
    let mut children: HashMap<u32, Vec<&Dent>> = HashMap::new();
    for d in &dents {
        children.entry(d.parent).or_default().push(d);
    }

    fs::create_dir_all(out_dir)?;

    let mut count = 0usize;
    let mut stack: Vec<(u32, PathBuf)> = vec![(ROOT_INO, out_dir.to_path_buf())];
    let mut visited: HashMap<u32, ()> = HashMap::new();

    while let Some((ino, dir_path)) = stack.pop() {
        if visited.insert(ino, ()).is_some() {
            continue; // guard against cycles
        }
        let Some(kids) = children.get(&ino) else {
            continue;
        };
        for d in kids {
            let child_path = dir_path.join(sanitize_component(&d.name));
            match d.itype {
                ITYPE_DIR => {
                    if fs::create_dir_all(&child_path).is_ok() {
                        count += 1;
                        stack.push((d.target, child_path));
                    }
                }
                ITYPE_REG => {
                    if write_regular_file(&child_path, d.target, &inodes, &data) {
                        count += 1;
                    }
                }
                ITYPE_LNK => {
                    if let Some(ino) = inodes.get(&d.target) {
                        let target = String::from_utf8_lossy(&ino.inline).to_string();
                        // Portable: record symlinks as text files (Windows-safe).
                        if fs::write(&child_path, format!("SYMLINK -> {target}")).is_ok() {
                            count += 1;
                        }
                    }
                }
                _ => {
                    // Special files (dev/fifo/sock): note as empty placeholder.
                    let _ = File::create(&child_path);
                    count += 1;
                }
            }
        }
    }

    Ok(count)
}

/// Assemble and write a regular file from its data blocks, truncated to the
/// inode size.
fn write_regular_file(
    path: &Path,
    ino: u32,
    inodes: &HashMap<u32, Inode>,
    data: &HashMap<u32, HashMap<u64, Vec<u8>>>,
) -> bool {
    let size = inodes.get(&ino).map(|i| i.size).unwrap_or(0);

    let mut out = match File::create(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    if let Some(blocks) = data.get(&ino) {
        let mut block_nos: Vec<u64> = blocks.keys().cloned().collect();
        block_nos.sort_unstable();
        for bn in block_nos {
            let expected_off = bn * UBIFS_BLOCK_SIZE;
            // Pad holes with zeros to keep byte offsets correct.
            let cur = out.stream_position().unwrap_or(0);
            if expected_off > cur {
                let hole = (expected_off - cur) as usize;
                let _ = out.write_all(&vec![0u8; hole]);
            }
            let _ = out.write_all(&blocks[&bn]);
        }
    }

    // Truncate to the exact inode size when known.
    if size > 0 {
        let _ = out.flush();
        if let Ok(f) = File::options().write(true).open(path) {
            let _ = f.set_len(size);
        }
    }
    true
}

/// Linear scan of the volume image collecting UBIFS nodes, validated by CRC-32.
fn scan_nodes(
    image: &[u8],
    inodes: &mut HashMap<u32, Inode>,
    dents: &mut Vec<Dent>,
    data: &mut HashMap<u32, HashMap<u64, Vec<u8>>>,
) {
    let mut off = 0usize;
    let n = image.len();

    while off + CH_SZ <= n {
        // UBIFS nodes are 8-byte aligned.
        if le32(image, off) != UBIFS_NODE_MAGIC {
            off += 8;
            continue;
        }

        let crc = le32(image, off + 4);
        // Common header: magic(0) crc(4) sqnum(8,u64) len(16,u32) node_type(20).
        let len = le32(image, off + 16) as usize;
        let node_type = image[off + 20];

        if len < CH_SZ || off + len > n {
            off += 8;
            continue;
        }

        // Validate CRC-32 over everything after the crc field. UBIFS uses the
        // Linux crc32() (init 0xFFFFFFFF, no final XOR), which is the bitwise
        // complement of the standard zlib CRC that flate2 computes.
        let mut c = Crc::new();
        c.update(&image[off + 8..off + len]);
        if (c.sum() ^ 0xFFFF_FFFF) != crc {
            off += 8;
            continue;
        }

        let node = &image[off..off + len];
        match node_type {
            INO_NODE => parse_ino(node, inodes),
            DENT_NODE => parse_dent(node, dents),
            DATA_NODE => parse_data(node, data),
            _ => {}
        }

        // Advance to the next 8-byte-aligned node.
        off += (len + 7) & !7;
    }
}

fn parse_ino(node: &[u8], inodes: &mut HashMap<u32, Inode>) {
    if node.len() < 160 {
        return;
    }
    let ino = le32(node, KEY_OFF); // key[0] = inode number
    let size = le64(node, 48);
    let mode = le32(node, 104);
    let data_len = le32(node, 112) as usize;

    let itype = mode_to_itype(mode);
    let mut inline = Vec::new();
    if itype == ITYPE_LNK && data_len > 0 && 160 + data_len <= node.len() {
        inline = node[160..160 + data_len].to_vec();
    }

    inodes.insert(ino, Inode { size, inline });
}

fn parse_dent(node: &[u8], dents: &mut Vec<Dent>) {
    if node.len() < 56 {
        return;
    }
    let parent = le32(node, KEY_OFF); // key[0] = parent inode
    let target = le32(node, 40); // low 32 bits of __le64 inum
    let itype = node[49];
    let nlen = le16(node, 50) as usize;
    if 56 + nlen > node.len() {
        return;
    }
    let name = String::from_utf8_lossy(&node[56..56 + nlen]).to_string();
    if name.is_empty() {
        return;
    }
    dents.push(Dent {
        parent,
        target,
        itype,
        name,
    });
}

fn parse_data(node: &[u8], data: &mut HashMap<u32, HashMap<u64, Vec<u8>>>) {
    if node.len() < DATA_NODE_SZ {
        return;
    }
    let ino = le32(node, KEY_OFF); // key[0] = inode number
    let block_no = (le32(node, KEY_OFF + 4) & 0x1FFF_FFFF) as u64; // key[1] low bits
    let out_len = le32(node, 40) as usize;
    let compr = le16(node, 44);
    let payload = &node[DATA_NODE_SZ..];

    let decompressed = match decompress_block(payload, compr, out_len) {
        Some(d) => d,
        None => return,
    };

    data.entry(ino).or_default().insert(block_no, decompressed);
}

/// Decompress a single UBIFS data block payload.
fn decompress_block(payload: &[u8], compr: u16, out_len: usize) -> Option<Vec<u8>> {
    match compr {
        COMPR_NONE => {
            let take = out_len.min(payload.len());
            Some(payload[..take].to_vec())
        }
        COMPR_LZO => match minilzo_rs::LZO::init() {
            Ok(lzo) => lzo.decompress(payload, out_len).ok(),
            Err(_) => None,
        },
        COMPR_ZLIB => inflate_raw(payload, out_len),
        COMPR_ZSTD => crate::utils::compression::decompress_zstd(payload).ok(),
        _ => None,
    }
}

/// Raw DEFLATE inflate (UBIFS uses headerless zlib streams).
fn inflate_raw(payload: &[u8], out_len: usize) -> Option<Vec<u8>> {
    use flate2::Decompress;
    use flate2::FlushDecompress;

    let mut d = Decompress::new(false); // false = raw deflate (no zlib header)
    let mut out = Vec::with_capacity(out_len.max(payload.len()));
    match d.decompress_vec(payload, &mut out, FlushDecompress::Finish) {
        Ok(_) => Some(out),
        Err(_) => {
            // Retry assuming a zlib header just in case.
            crate::utils::compression::decompress_zlib(payload).ok()
        }
    }
}

fn mode_to_itype(mode: u32) -> u8 {
    match mode & 0o170000 {
        0o040000 => ITYPE_DIR,
        0o120000 => ITYPE_LNK,
        0o100000 => ITYPE_REG,
        _ => 0xFF,
    }
}

/// Make a single path component safe on the host filesystem.
fn sanitize_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();
    match cleaned.trim() {
        "" | "." | ".." => "_".to_string(),
        other => other.to_string(),
    }
}

// --- little-endian helpers --------------------------------------------------

fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn le64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off], b[off + 1], b[off + 2], b[off + 3], b[off + 4], b[off + 5], b[off + 6], b[off + 7],
    ])
}
