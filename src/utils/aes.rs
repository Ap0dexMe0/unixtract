//! AES encryption/decryption utilities.
//!
//! Provides centralized implementations for all AES modes used across the
//! various firmware format extractors. Instead of duplicating AES logic in
//! each format module, all AES operations should go through this module.

use aes::{Aes128, Aes256};
use cbc::{Decryptor as CbcDecryptor, cipher::{block_padding::Pkcs7, block_padding::NoPadding, BlockDecryptMut, KeyIvInit}};
use ecb::{Decryptor as EcbDecryptor, cipher::{KeyInit, generic_array::GenericArray}};

type Aes128CbcDec = CbcDecryptor<Aes128>;
type Aes128EcbDec = EcbDecryptor<Aes128>;
type Aes256EcbDec = EcbDecryptor<Aes256>;

// ── AES-128 CBC ─────────────────────────────────────────────────────────────

/// Decrypt data using AES-128-CBC with PKCS7 padding.
pub fn decrypt_aes128_cbc_pcks7(encrypted_data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();
    let decryptor = Aes128CbcDec::new(key.into(), iv.into());
    let decrypted = decryptor.decrypt_padded_mut::<Pkcs7>(&mut data)
        .map_err(|e| format!("AES-128-CBC-PKCS7 decryption error: {:?}", e))?;

    Ok(decrypted.to_vec())
}

/// Decrypt data using AES-128-CBC with no padding.
pub fn decrypt_aes128_cbc_nopad(encrypted_data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();
    let decryptor = Aes128CbcDec::new(key.into(), iv.into());

    let decrypted = decryptor
        .decrypt_padded_mut::<NoPadding>(&mut data)
        .map_err(|e| format!("AES-128-CBC-NoPad decryption error: {:?}", e))?;

    Ok(decrypted.to_vec())
}

// ── AES-128 ECB ─────────────────────────────────────────────────────────────

/// Decrypt data using AES-128-ECB (raw block decryption, no padding).
pub fn decrypt_aes128_ecb(key: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = ciphertext.to_vec();

    let mut decryptor = Aes128EcbDec::new(key.into());
    for chunk in buffer.chunks_exact_mut(16) {
        let block: &mut [u8; 16] = chunk.try_into()?;
        decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
    }

    Ok(buffer)
}

// ── AES-256 ECB ─────────────────────────────────────────────────────────────

/// Decrypt data using AES-256-ECB (raw block decryption, no padding).
pub fn decrypt_aes256_ecb(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = ciphertext.to_vec();

    let mut decryptor = Aes256EcbDec::new(key.into());
    for chunk in buffer.chunks_exact_mut(16) {
        let block: &mut [u8; 16] = chunk.try_into()?;
        decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
    }

    Ok(buffer)
}

// ── AES ECB auto-detect key size ────────────────────────────────────────────

/// Decrypt data using AES-ECB, automatically selecting AES-128 or AES-256
/// based on the key length (16 bytes → AES-128, 32 bytes → AES-256).
///
/// Returns an error if the key length is neither 16 nor 32 bytes.
pub fn decrypt_aes_ecb_auto(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = ciphertext.to_vec();

    match key.len() {
        16 => {
            let key_array: [u8; 16] = key.try_into()?;
            let mut decryptor = Aes128EcbDec::new(&key_array.into());
            for chunk in buffer.chunks_exact_mut(16) {
                let block: &mut [u8; 16] = chunk.try_into()?;
                decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
            }
        }
        32 => {
            let key_array: [u8; 32] = key.try_into()?;
            let mut decryptor = Aes256EcbDec::new(&key_array.into());
            for chunk in buffer.chunks_exact_mut(16) {
                let block: &mut [u8; 16] = chunk.try_into()?;
                decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
            }
        }
        _ => return Err(format!("Invalid AES key length: {} (expected 16 or 32)", key.len()).into()),
    }

    Ok(buffer)
}
