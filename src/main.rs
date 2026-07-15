mod error;
mod formats;
mod keys;
mod utils;

use clap::Parser;
use std::path::{Path, PathBuf};
use std::io::{self, Seek, SeekFrom, Write};
use std::fs::{self, File};
use crate::formats::{Format, get_registry};
use crate::error::UnixtractError;

#[derive(Parser, Debug)]
#[command(
    name = "unixtract",
    version,
    about = "Firmware package analyzer and extractor",
    long_about = "unixtract analyzes and extracts firmware package formats commonly found in\n\
                  TVs, Blu-ray players, and AV devices. It supports 35+ formats with built-in\n\
                  decryption and decompression capabilities.",
    after_help = "\
EXAMPLES:\n\
\n\
  # Single file analysis\n\
  unixtract --file-input firmware.bin\n\
  unixtract --file-input firmware.bin --output output/\n\
  unixtract --file-input firmware.bin --lazy-run\n\
  unixtract --file-input firmware.bin --build-prop\n\
  unixtract --file-input firmware.bin --dump-keys\n\
  unixtract --file-input firmware.bin --verbose\n\
\n\
  # Bulk / directory processing\n\
  unixtract --dir-input firmware_older/\n\
  unixtract --dir-input firmware_older/ --output bulk_output/\n\
  unixtract --dir-input firmware_older/ --lazy-run\n\
  unixtract --dir-input firmware_older/ --build-prop\n\
  unixtract --dir-input firmware_older/ --dump-keys\n\
  unixtract --dir-input firmware_older/ --output bulk_output/ --verbose\n\
\n\
  # Combined usage\n\
  unixtract --file-input firmware.bin --lazy-run --build-prop --verbose\n\
  unixtract --dir-input firmware_older/ --output extracted_fw/ --verbose --build-prop\n\
  unixtract --file-input firmware.bin --dump-keys\n\
  unixtract --file-input firmware.bin --lazy-run --dump-keys"
)]
struct Args {
    /// Single firmware binary input
    #[arg(long = "file-input")]
    file_input: Option<String>,

    /// Directory containing multiple firmware binaries for bulk processing
    #[arg(long = "dir-input")]
    dir_input: Option<String>,

    /// Output path for extracted data (default: _<INPUT>)
    #[arg(long = "output")]
    output: Option<String>,

    /// Enable lazy-run mode — minimal processing for faster analysis
    #[arg(long = "lazy-run")]
    lazy_run: bool,

    /// Extract and display firmware build properties and metadata
    #[arg(long = "build-prop")]
    build_prop: bool,

    /// Dump built-in decryption keys
    #[arg(long = "dump-keys")]
    dump_keys: bool,

    /// List supported formats and exit
    #[arg(long = "list-formats")]
    list_formats: bool,

    /// Increase verbosity level (repeat for more)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,
}

pub enum InputTarget {
    File(File),
    Directory(PathBuf),
}

pub struct AppContext {
    pub input: InputTarget,
    pub input_path: Option<PathBuf>,
    pub output_dir: PathBuf,
    pub options: Vec<String>,
    pub dry_run: bool,
    pub lazy_run: bool,
    pub build_prop: bool,
    pub dump_keys: bool,
    pub quiet: bool,
    pub verbose: u8,
}

impl AppContext {
    pub fn file(&self) -> Option<&File> {
        match &self.input {
            InputTarget::File(f) => Some(f),
            _ => None,
        }
    }

    pub fn input_path(&self) -> Option<&Path> {
        self.input_path.as_deref()
    }

    pub fn dir(&self) -> Option<&PathBuf> {
        match &self.input {
            InputTarget::Directory(p) => Some(p),
            _ => None,
        }
    }

    pub fn has_option(&self, option: &'static str) -> bool {
        self.options.iter().any(|o| o == option)
    }
}

/// Clear the terminal screen
fn clear_terminal() {
    // ANSI escape sequence to clear screen and move cursor to top-left
    eprint!("\x1B[2J\x1B[H");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // --- Handle --list-formats (doesn't require input) ---
    if args.list_formats {
        let formats = get_registry();
        eprintln!("Supported formats ({} total):", formats.len());
        for (i, fmt) in formats.iter().enumerate() {
            eprintln!("  {:2}. {}", i + 1, fmt.name);
        }
        return Ok(());
    }

    // --- Validate mutually exclusive input modes ---
    let (target_path, is_file_mode) = match (&args.file_input, &args.dir_input) {
        (Some(f), None) => (PathBuf::from(f), true),
        (None, Some(d)) => (PathBuf::from(d), false),
        (Some(_), Some(_)) => {
            return Err("Cannot specify both --file-input and --dir-input at the same time".into());
        }
        (None, None) => {
            return Err("Either --file-input or --dir-input must be provided".into());
        }
    };

    // --- Logger initialization ---
    let log_level = match args.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp(None)
        .format_target(false)
        .format_module_path(false)
        .format(|buf, record| {
            match record.level() {
                log::Level::Error => writeln!(buf, "\x1b[31m[ERROR]\x1b[0m {}", record.args()),
                log::Level::Warn => writeln!(buf, "\x1b[33m[WARN]\x1b[0m  {}", record.args()),
                log::Level::Info => writeln!(buf, "\x1b[36m{}\x1b[0m", record.args()),
                log::Level::Debug => writeln!(buf, "\x1b[32m[DBG]\x1b[0m   {}", record.args()),
                log::Level::Trace => writeln!(buf, "\x1b[90m[TRC]\x1b[0m   {}", record.args()),
            }
        })
        .init();

    clear_terminal();

    log::info!("unixtract v{}", env!("CARGO_PKG_VERSION"));

    // --- Output directory ---
    let output_path_str = if let Some(ref out) = args.output {
        out.clone()
    } else {
        let fname = target_path.file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| UnixtractError::Other("Invalid input file name".to_string()))?;
        format!("_{}", fname)
    };
    let output_directory_path = PathBuf::from(&output_path_str);

    if output_directory_path.exists() {
        if output_directory_path.is_dir() {
            let is_empty = fs::read_dir(&output_directory_path)?.next().is_none();
            if !is_empty {
                log::warn!("Output folder already exists and is NOT empty! Files may be overwritten.");
                eprintln!("Press Enter if you want to continue...");
                io::stdin().read_line(&mut String::new())?;
            }
        }
    }

    // --- Build AppContext ---
    let app_ctx = if is_file_mode {
        let file = File::open(&target_path)?;
        AppContext {
            input: InputTarget::File(file),
            input_path: Some(target_path.clone()),
            output_dir: output_directory_path,
            options: Vec::new(),
            dry_run: args.lazy_run,
            lazy_run: args.lazy_run,
            build_prop: args.build_prop,
            dump_keys: args.dump_keys,
            quiet: args.verbose == 0,
            verbose: args.verbose,
        }
    } else {
        AppContext {
            input: InputTarget::Directory(target_path.clone()),
            input_path: Some(target_path.clone()),
            output_dir: output_directory_path,
            options: Vec::new(),
            dry_run: args.lazy_run,
            lazy_run: args.lazy_run,
            build_prop: args.build_prop,
            dump_keys: args.dump_keys,
            quiet: args.verbose == 0,
            verbose: args.verbose,
        }
    };

    let formats: Vec<Format> = get_registry();

    for format in formats {
        if let Some(ctx) = (format.detector_func)(&app_ctx)? {
            log::info!("\n{} detected!", format.name);

            if app_ctx.lazy_run {
                log::info!("Lazy-run — skipping extraction.");
                return Ok(());
            }

            // Reset seek of the file if present
            if let Some(mut file) = app_ctx.file() {
                file.seek(SeekFrom::Start(0))?;
            }

            (format.extractor_func)(&app_ctx, ctx)?;

            log::info!("\nExtraction finished! Saved extracted files to {}", output_path_str);
            return Ok(());
        }
    }

    log::warn!("\nInput format not recognized!");
    Err("Unrecognized input format".into())
}
