use crate::util::*;
use crypto::aes::{self, KeySize};
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::{blockmodes, buffer};

pub fn run(fname: &str, key: &str, iv: &str) -> Result<String, Box<std::error::Error>> {
    let b64 = std::fs::read_to_string(fname)?.replace("\n", "");
    let ct = base64::decode(&b64)?;
    let pt = aes_cbc_decrypt(&ct, key.as_bytes(), iv.as_bytes()).unwrap();
    //println!("{}", std::str::from_utf8(&pt).unwrap());
    let pt_padded = pad_pkcs7(&pt, 16);
    let ct = aes_cbc_encrypt(&pt_padded, key.as_bytes(), iv.as_bytes()).unwrap();
    Ok(base64::encode(&ct))
}
