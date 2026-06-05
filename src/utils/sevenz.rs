use std::path::PathBuf;
use log::info;

#[allow(dead_code)]
pub fn decompress_7z(data: &[u8], output_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    info!("- Decompressing 7z archive...");
    sevenz_rust2::decompress(std::io::Cursor::new(data.to_vec()), &output_dir)?;
    Ok(())
}

#[allow(dead_code)]
pub fn decompress_7z_file(file_path: &std::path::Path, output_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    info!("- Decompressing 7z file...");
    sevenz_rust2::decompress_file(file_path, &output_dir)?;
    Ok(())
}
