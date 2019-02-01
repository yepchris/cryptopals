use crate::util::*;

pub fn run(fname: &str) -> Result<String, Box<std::error::Error>> {
    let b64 = std::fs::read_to_string(fname)?.replace("\n", "");
    let ct = base64::decode(&b64)?;
    let ct_len = ct.len();
    let mut likely_keysize = 0;
    let mut lowest_distance = 0.0;
    let mut key = vec![];

    // normalized, mean Hamming distance among 4 blocks should be enough
    let block_limit = 4;
    for key_size in 2..40 {
        let normalized_hamming = match mean_hamming(&ct, key_size, block_limit) {
            Some(h) => h,
            None => continue,
        };

        if normalized_hamming < lowest_distance || lowest_distance == 0.0 {
            lowest_distance = normalized_hamming;
            likely_keysize = key_size;
        }
    }

    for chunk in transpose(&ct.clone(), likely_keysize).iter() {
        key.push(brute_char(&chunk).0);
    }

    let pt = xor(&ct, &key);
    Ok(std::str::from_utf8(&pt)?.to_string())
}
