// MSD OUITH parsers
pub mod msd_ouith_parser_old;
pub mod msd_ouith_parser_tizen_1_8;
pub mod msd_ouith_parser_tizen_1_9;

// COMMON MSD FUNCTIONS
use crate::utils::aes::decrypt_aes128_cbc_pcks7;

/// Decrypt "Salted__" format data using OpenSSL-compatible key derivation
/// (MD5 of passphrase+salt for key, MD5 of key+passphrase+salt for IV).
pub fn decrypt_aes_salted_old(encrypted_data: &[u8], passphrase_bytes: &Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if encrypted_data.len() < 16 || encrypted_data[0..8].to_vec() != b"Salted__" {
        return Err("Invalid encrypted data!".into());
    }
    let salt = &encrypted_data[8..16];

    // key = MD5(passphrase + salt)
    let mut key_input = Vec::new();
    key_input.extend_from_slice(&passphrase_bytes);
    key_input.extend_from_slice(&salt);
    let key_md5 = md5::compute(&key_input);

    // iv = MD5(key + passphrase + salt)
    let mut iv_input = Vec::new();
    iv_input.extend_from_slice(&key_md5.0);
    iv_input.extend_from_slice(&passphrase_bytes);
    iv_input.extend_from_slice(&salt);
    let iv_md5 = md5::compute(&iv_input);

    let key: [u8; 16] = key_md5.0;
    let iv: [u8; 16] = iv_md5.0;
    decrypt_aes128_cbc_pcks7(&encrypted_data[16..], &key, &iv)
}

/// Decrypt "Salted__" format data using Tizen-style key derivation
/// (passphrase used directly as key, MD5 of salt for IV).
pub fn decrypt_aes_salted_tizen(encrypted_data: &[u8], passphrase_bytes: &Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if encrypted_data.len() < 16 || encrypted_data[0..8].to_vec() != b"Salted__" {
        return Err("Invalid encrypted data!".into());
    }
    let salt = &encrypted_data[8..16];

    // iv = MD5(salt)
    let iv = md5::compute(&salt);
    let key: [u8; 16] = passphrase_bytes.as_slice().try_into()
        .map_err(|_| "Passphrase must be 16 bytes for AES-128")?;
    let iv: [u8; 16] = iv.0;

    decrypt_aes128_cbc_pcks7(&encrypted_data[16..], &key, &iv)
}

/// Decrypt data using Tizen-style AES-128-CBC with passphrase as key and
/// MD5 of salt as IV.
pub fn decrypt_aes_tizen(encrypted_data: &[u8], passphrase_bytes: &Vec<u8>, salt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // iv = MD5(salt)
    let iv = md5::compute(&salt);
    let key: [u8; 16] = passphrase_bytes.as_slice().try_into()
        .map_err(|_| "Passphrase must be 16 bytes for AES-128")?;
    let iv: [u8; 16] = iv.0;

    decrypt_aes128_cbc_pcks7(&encrypted_data, &key, &iv)
}
