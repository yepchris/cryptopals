use crate::util::*;

pub fn run(fname: &str, key: &str) -> Result<String, Box<std::error::Error>> {
    let b64 = std::fs::read_to_string(fname)?.replace("\n", "");
    let ct = base64::decode(&b64)?;

    let pt = unpad_pkcs7(&aes_ecb_decrypt(&ct, key.as_bytes())?);
    Ok(std::str::from_utf8(&pt)?.to_string())
}
