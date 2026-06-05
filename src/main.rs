mod error;
mod formats;
mod keys;
mod utils;

use clap::Parser;
use std::path::PathBuf;
use std::io::{self, Seek, SeekFrom, Write};
use std::fs::{self, File};
use crate::formats::{Format, get_registry};
use crate::error::UnixtractError;

#[derive(Parser, Debug)]
#[command(
    name = "unixtract",
    version,
    about = "Firmware extractor for various file formats",
    long_about = "unixtract analyzes and extracts firmware package formats commonly found \
                  in TVs, Blu-Ray players, and AV devices. It supports 35+ different formats \
                  with built-in decryption and decompression capabilities."
)]
struct Args {
    /// The target file or directory to analyze/extract
    #[arg(required_unless_present = "list_formats")]
    input_target: Option<String>,

    /// Folder to save extracted files to (default: _<INPUT_TARGET>)
    output_directory: Option<String>,

    /// Format-specific or global options (can be used multiple times)
    #[arg(short, long)]
    options: Vec<String>,

    /// List supported formats and exit
    #[arg(long)]
    list_formats: bool,

    /// Only detect the format, do not extract
    #[arg(long)]
    dry_run: bool,

    /// Quiet mode — suppress non-error output
    #[arg(short, long)]
    quiet: bool,

    /// Verbose mode — show detailed progress information (use -vv for trace)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

pub enum InputTarget {
    File(File),
    Directory(PathBuf),
}

pub struct AppContext {
    pub input: InputTarget,
    pub output_dir: PathBuf,
    pub options: Vec<String>,
    pub dry_run: bool,
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

    // Clear the terminal on execution
    if !args.quiet {
        clear_terminal();
    }

    // Initialize logger based on verbosity level
    // Default (no flags): show info-level output (normal progress)
    // -q: errors only
    // -v: info (same as default, explicit)
    // -vv: debug level (more details)
    // -vvv: trace level (everything)
    let log_level = if args.quiet {
        "error"
    } else {
        match args.verbose {
            0 => "info",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp(None)
        .format_target(false)
        .format_module_path(false)
        .format(|buf, record| {
            // Clean format: just the message for info/debug/trace
            // Add level prefix for warn/error so they stand out
            match record.level() {
                log::Level::Error => writeln!(buf, "[ERROR] {}", record.args()),
                log::Level::Warn => writeln!(buf, "[WARN]  {}", record.args()),
                log::Level::Info => writeln!(buf, "{}", record.args()),
                log::Level::Debug => writeln!(buf, "[DBG]   {}", record.args()),
                log::Level::Trace => writeln!(buf, "[TRC]   {}", record.args()),
            }
        })
        .init();

    // Handle --list-formats
    if args.list_formats {
        let formats = get_registry();
        eprintln!("Supported formats ({} total):", formats.len());
        for (i, fmt) in formats.iter().enumerate() {
            eprintln!("  {:2}. {}", i + 1, fmt.name);
        }
        return Ok(());
    }

    log::info!("unixtract v{}", env!("CARGO_PKG_VERSION"));

    let target_path_str = args.input_target.as_deref().unwrap_or("");
    let target_path = PathBuf::from(target_path_str);

    let output_path_str = if let Some(ref out) = args.output_directory {
        out.clone()
    } else {
        format!("_{}", target_path.file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| UnixtractError::Other("Invalid input file name".to_string()))?)
    };
    let output_directory_path = PathBuf::from(&output_path_str);

    if output_directory_path.exists() {
        if output_directory_path.is_dir() {
            let is_empty = fs::read_dir(&output_directory_path)?.next().is_none();
            if !is_empty && !args.quiet {
                log::warn!("Output folder already exists and is NOT empty! Files may be overwritten.");
                eprintln!("Press Enter if you want to continue...");
                io::stdin().read_line(&mut String::new())?;
            }
        }
    }

    // === DEFAULT MODE (original behavior) ===
    let app_ctx;

    if target_path.is_file() {
        let file = File::open(&target_path)?;
        app_ctx = AppContext {
            input: InputTarget::File(file),
            output_dir: output_directory_path,
            options: args.options,
            dry_run: args.dry_run,
            quiet: args.quiet,
            verbose: args.verbose,
        };
    } else if target_path.is_dir() {
        app_ctx = AppContext {
            input: InputTarget::Directory(target_path),
            output_dir: output_directory_path,
            options: args.options,
            dry_run: args.dry_run,
            quiet: args.quiet,
            verbose: args.verbose,
        };
    } else {
        return Err("Invalid input path!".into());
    }

    let formats: Vec<Format> = get_registry();

    for format in formats {
        if let Some(ctx) = (format.detector_func)(&app_ctx)? {
            log::info!("\n{} detected!", format.name);

            if app_ctx.dry_run {
                log::info!("Dry run — skipping extraction.");
                return Ok(());
            }

            // Reset seek of the file if present
            if let Some(mut file) = app_ctx.file() {
                file.seek(SeekFrom::Start(0))?;
            }

            (format.extractor_func)(&app_ctx, ctx)?;

            // Extractor returned with no error
            log::info!("\nExtraction finished! Saved extracted files to {}", output_path_str);
            return Ok(());
        }
    }

    log::warn!("\nInput format not recognized!");
    Err("Unrecognized input format".into())
}
