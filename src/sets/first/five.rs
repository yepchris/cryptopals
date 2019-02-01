use crate::util;

pub fn run(pt: &str, key: &str) -> Result<String, Box<std::error::Error>> {
    Ok(hex::encode(util::xor(pt.as_bytes(), key.as_bytes())))
}
