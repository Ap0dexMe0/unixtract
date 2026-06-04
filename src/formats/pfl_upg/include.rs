use crate::utils::common;
use crate::utils::aes::decrypt_aes256_ecb;
use binrw::BinRead;
use crate::keys;
use rsa::{RsaPublicKey, BigUint};

pub fn try_find_key(sig: &[u8], ciphertext: &[u8]) -> Result<Option<(String, [u8; 32])>, Box<dyn std::error::Error>> {
    let mut result: Option<(String, [u8; 32])> = None;

    for (name, n_hex) in keys::PFLUPG {
        let n = BigUint::from_bytes_be(&hex::decode(n_hex)?);
        let e = BigUint::from_bytes_be(&hex::decode("010001")?);
        let pubkey = RsaPublicKey::new(n, e)?;

        let sig_int = BigUint::from_bytes_le(&sig);
        let dec_int = rsa::hazmat::rsa_encrypt(&pubkey, &sig_int)?;
        let dec_sig = dec_int.to_bytes_le();

        let aes_key: [u8; 32] = dec_sig[20..52].try_into().unwrap();
        let dec_ciphertext = decrypt_aes256_ecb(&aes_key, &ciphertext)?;

        // Needs to start with null-terminated filename string
        let end = match dec_ciphertext.iter().position(|&b| b == 0) {
            Some(pos) => pos,
            None => continue,       // There is no 0, continue
        };
        let fname = &dec_ciphertext[..end];
        if fname.len() > 1 && fname.is_ascii() {       // Is ASCII filename
            result = Some((name.to_string(), aes_key));
            break
        }
    }

    Ok(result)
}

#[derive(BinRead)]
pub struct Header {
    _magic_bytes: [u8; 8],
    pub header_size: u32,   //data start
    pub data_size: u32,
        _crc32: u32,
        pub mask: u32,
        _data_size_decompressed: u32,
        _padding2: u32,
        description_bytes: [u8; 512],
}
impl Header {
    pub fn description(&self) -> String {
        common::string_from_bytes(&self.description_bytes).replace('\r', "\n")
    }
    pub fn is_encrypted(&self) -> bool {
        (self.mask & 0x2000_0000) != 0
    }
}

#[derive(BinRead)]
pub struct FileHeader {
    file_name_bytes: [u8; 60],
    pub real_size: u32,
        pub stored_size: u32,
        pub header_size: u32,
    pub attributes: [u8; 4],
}
impl FileHeader {
    pub fn file_name(&self) -> String {
        common::string_from_bytes(&self.file_name_bytes)
    }
    pub fn is_folder(&self) -> bool {
        (self.attributes[3] & (1 << 1)) != 0
    }
    pub fn has_extended_name(&self) -> bool {
        (self.attributes[2] & (1 << 7)) != 0
    }
    pub fn is_package(&self) -> bool {
        (self.attributes[3] & (1 << 2)) != 0
    }
}
