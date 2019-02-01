use crate::util::*;

pub fn run(input: &str, block_len: u8) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(pad_pkcs7(input.as_bytes(), block_len))
}
