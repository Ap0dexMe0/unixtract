# unixtract

> A fast, dependency-free firmware extractor for TVs, Blu-ray players, set-top boxes, and other AV devices.

`unixtract` analyzes and unpacks a wide range of proprietary firmware package formats, with built-in decryption and decompression. It is written entirely in Rust with no external runtime dependencies, so a single binary runs on **Windows, Linux, macOS, and Android**.

This project is a fork of [theubusu/unixtract](https://github.com/theubusu/unixtract), adding extra formats, features, and fixes.

> [!NOTE]
> This project is under active development — errors may occur. Bug reports and feature requests are welcome via the issue tracker.

> [!IMPORTANT]
> `unixtract` is an **extraction** tool only. It is **not**, and will never be, designed to re-pack extracted files.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Supported Formats](#supported-formats)
- [Format Options](#format-options)
- [Notes on Keys](#notes-on-keys)
- [License](#license)

---

## Features

- **35+ firmware formats** across major TV/AV silicon vendors (MStar, MediaTek, Novatek, Amlogic, Broadcom…).
- **Built-in decryption** (AES, DES, ECB/CBC, RSA) and **decompression** (LZO, LZ4, LZMA/XZ, zlib/gzip, bzip2, zstd, LZHS, sparse).
- **Recursive extraction** — container formats automatically unpack their inner payloads.
- **NAND-aware** — handles raw NAND dumps, OOB/spare stripping, and UBI/UBIFS rootfs images.
- **Single static binary** — no interpreters, no system libraries.
- **Bulk mode** — process an entire directory of firmware in one run.

## Installation

### Prebuilt binaries

Download the latest automated build for Windows and Linux x86-64 from the [nightly builds](https://nightly.link/Ap0dexMe0/unixtract/workflows/rust/main).

### From source

```sh
git clone https://github.com/Ap0dexMe0/unixtract
cd unixtract
cargo build --release
```

The resulting binary is written to `target/release/unixtract`.

## Usage

```sh
unixtract [OPTIONS]
```

### Input modes (mutually exclusive)

| Flag | Description |
| --- | --- |
| `--file-input <FILE>` | Extract a single firmware binary |
| `--dir-input <DIR>` | Bulk-process every firmware binary in a directory |

### Options

| Flag | Description |
| --- | --- |
| `--output <PATH>` | Output path for extracted data (default: `_<INPUT>`) |
| `--lazy-run` | Detect/scan only — skip extraction (fast analysis) |
| `--build-prop` | Extract and display firmware build properties and metadata |
| `--dump-keys` | Dump the built-in decryption keys |
| `--list-formats` | List all supported formats and exit |
| `-v, --verbose` | Increase verbosity (repeat for more detail) |
| `-h, --help` | Print help information |
| `-V, --version` | Print version information |

### Examples

```sh
# Single file
unixtract --file-input firmware.bin
unixtract --file-input firmware.bin --output extracted/ --verbose

# Bulk directory
unixtract --dir-input firmware_dump/ --output out/

# Quick analysis without extracting
unixtract --file-input firmware.bin --lazy-run
```

## Supported Formats

> Entries marked **keys** depend on decryption keys — see [`keys.rs`](src/keys.rs). Most common keys are bundled.
> Entries marked **hdrs** support the `dump_dec_hdrs` option.

### TV / SoC firmware

| Format | Used in | Notes |
| --- | --- | --- |
| **MStar upgrade bin** | Many MStar-based TVs (Hisense, Toshiba…) | LZOP, LZ4, LZMA, sparse-write support · hdrs |
| **MStar upgrade bin (Secure, old)** | Older MStar TVs with secure (encrypted+signed) upgrades | Default upgrade key only |
| **MStar UNFD NAND dump** | Raw MStar NAND dumps prefixed with `MSTARSEMIUNFDCIS` (e.g. `TH58NVG2S3HTA00.bin`) | Derives NAND geometry; carves boot banks, `rootfs_ubi.bin`, and `nand_data.bin`; recurses into inner formats; writes `cis_info.txt` |
| **UBI / UBIFS NAND rootfs** | NAND Linux rootfs images (`UBI#` header), e.g. carved `rootfs_ubi.bin` | Strips interleaved NAND OOB, tolerates vendor header quirks, reconstructs volumes, CRC-validated linear UBIFS scan (LZO/zlib/zstd) |
| **MediaTek PKG (New)** | Newer MediaTek TVs (TCL, Hisense, Sony, Philips, CVT…) | keys (Philips, Sony) · hdrs |
| **MediaTek PKG (Old)** | Older MediaTek TVs (Philips, Sony, Hisense…) | Full decrypt + decompress · hdrs |
| **Novatek PKG (NFWB)** | Older Novatek TVs (LG, Philips) | All files supported |
| **Novatek TIMG** | Newer Novatek TVs (TPVision, Hisense, TCL…) | All files supported |
| **Amlogic burning image** | Android TVs and boxes | V1 not supported (no sample) · thanks to [ampack](https://github.com/7Ji/ampack) |
| **EPK v1** | LG TVs before ~2010 | thanks to [epk2extract](https://github.com/openlgtv/epk2extract) |
| **EPK v2** | LG TVs since ~2010 | keys · hdrs · thanks to [epk2extract](https://github.com/openlgtv/epk2extract) |
| **EPK v3** | LG webOS TVs | keys · hdrs · thanks to [epk2extract](https://github.com/openlgtv/epk2extract) |
| **MSD 1.0** | Samsung TVs 2013–2015 | keys · hdrs · thanks to [msddecrypt](https://github.com/bugficks/msddecrypt) |
| **MSD 1.1** | Samsung TVs 2016+ | keys (2015–2018, 2020) · hdrs · thanks to [msddecrypt](https://github.com/bugficks/msddecrypt) |
| **Samsung (`*.img.sec` folder)** | Samsung TVs pre-2013 | keys · thanks to [samygo-patcher](https://github.com/george-hopkins/samygo-patcher) |
| **Philips UPG** (`Autorun.upg`, `2SWU3TXV`) | Philips pre-TPVision TVs 200?–2013, some Sony TVs | keys · thanks to [pflupg-tool](https://github.com/frederic/pflupg-tool) |
| **Roku** | Roku TVs / players | Some inner images remain encrypted |
| **GX DVB** | Cheap NationalChip GX-based DVB tuners | All files supported |
| **CD5** | Some Samsung TV tuners / Irdeto-based tuners | Decryption not supported |
| **TSB Bin** | Older Toshiba TVs | hdrs |

### Blu-ray / AV device firmware

| Format | Used in | Notes |
| --- | --- | --- |
| **MediaTek BDP** | MediaTek Blu-ray players (LG, Samsung, Philips, Panasonic…) | Some older files may fail |
| **Philips BDP** | Philips MediaTek-based Blu-ray players / HTS | Main partition may be encrypted — try `philips_bdp:decrypt` |
| **Sony BDP** | Sony MediaTek-based Blu-ray players | keys (up to MSB29) · thanks to [s390-firmware](http://malcolmstagg.com/bdp/s390-firmware.html) |
| **Funai BDP** | Funai / Funai-made Philips Blu-ray & HTS (USA) | — |
| **Funai MStar** | MStar-based Funai / Philips TVs (USA) | Inner SoC part via `mstar_secure_old` |
| **Funai UPG** | Some Funai TVs | keys |
| **Funai UPG PHL** | Funai / Philips TVs (USA) | keys |
| **Panasonic Blu-ray** (`PANA_DVD/ESD/EUSB.FRM`) | Panasonic Blu-ray players & recorders | keys (≤2014, some 2018) · hdrs |
| **INVINCIBLE_IMAGE** | LG Broadcom Blu-ray players | Key ID 1 (<2010) unsupported; extract split `.ROM-00/.ROM-01` together |
| **RUF** | Samsung Broadcom Blu-ray players | keys |
| **RVP / MVP** | Sharp Blu-ray players / recorders | Older XOR-encrypted types only |
| **Onkyo** | Onkyo AVRs and AV devices | Newer encryption unsupported · hdrs · thanks to [divideoverflow](http://divideoverflow.com/2014/04/decrypting-onkyo-firmware-files/) |

### Panasonic TV firmware

| Format | Used in | Notes |
| --- | --- | --- |
| **SDDL.SEC** | Panasonic TVs | Based on [sddl_dec](https://github.com/theubusu/sddl_dec) |
| **SDBoot** | Panasonic TVs (SD boot) | Single known sample — support may vary |
| **SDImage** (`SDImage.bin`) | Some 2010 USA Panasonic TVs | Decryption not yet supported |

### Generic / other

| Format | Used in | Notes |
| --- | --- | --- |
| **Android OTA `payload.bin`** | Android devices, phones, TVs | Some compression methods unsupported |
| **Raw eMMC user area** | eMMC dumps with `0x5840` partition descriptors | Dumps `<partition>.bin` + `partition_map.txt` |
| **BDL** | Enterprise HP printers | All files supported |
| **PUP** | Sony PlayStation 4/5 | Requires a decrypted file · thanks to [ps4-pup-unpacker](https://github.com/Zer0xFF/ps4-pup-unpacker) |
| **SLP** | Samsung Tizen-based NX cameras | All files supported |

## Format Options

Format-specific options are passed by name. Example: `mstar:keep_unknown`.

| Option | Effect |
| --- | --- |
| `mstar:keep_unknown` | Save data with unknown destination |
| `mstar_secure_old:keep_decrypted` | Keep the decrypted file (deleted by default) |
| `msd10:save_cmac` | Save CMAC data skipped by default |
| `msd:print_ouith` | Print the entire parsed OUITH header |
| `mtk_pkg:no_del_comp` | Keep LZHS compressed partition after decompressing |
| `pana_dvd:split_main` | Split the MAIN module into separate partitions |
| `pfl_upg:no_extract_inner_upg` | Do not auto-extract inner UPGs (may avoid collisions) |
| `philips_bdp:decrypt` | Decrypt the main partition |
| `sddl_sec:save_extra` | Save `SDIT.FDI` and `.TXT` files skipped by default |
| `sddl_sec:split_peaks` | Split the PEAKS module into partitions (older files) |
| `sddl_sec:no_decomp_peaks` | Do not auto-decompress when splitting PEAKS |

## Notes on Keys

Many formats require decryption keys stored in [`src/keys.rs`](src/keys.rs). The most common publicly known keys are bundled. Use `--dump-keys` to list what is available. If extraction of a key-dependent format fails, the required key may simply not be present.

## License

Licensed under the **GNU General Public License v3.0**.
