use crate::util;

pub fn run(fname: &str) -> Result<String, Box<std::error::Error>> {
    let b64 = std::fs::read_to_string(fname)?.replace("\n", "");
    let ct = base64::decode(&b64)?;
    let ct_len = ct.len();
    let mut likely_keysize = 0;
    let mut lowest_distance = 0.0;
    let mut key = vec![];

    for keysize in 2..40 {
        let mut chunks = vec![];
        let mut distances = 0;

        // get 4 chunks
        let i = 0;
        for i in 0..4 {
            let j = keysize * (i + 1);
            if j >= ct_len {
                break;
            }
            chunks.push(ct[keysize * i..j].to_vec());
        }

        // sum distances between all chunks
        for i in 0..3 {
            for j in 0..3 {
                if i < j + 1 {
                    distances += util::hamming(&chunks[i], &chunks[j + 1]).unwrap();
                }
            }
        }

        let avg = distances as f64 / 6.0;
        let normalized = avg / keysize as f64;

        if normalized < lowest_distance || lowest_distance == 0.0 {
            lowest_distance = normalized;
            likely_keysize = keysize;
        }
    }

    for chunk in util::transpose(&ct.clone(), likely_keysize).iter() {
        key.push(util::brute_char(&chunk).0);
    }

    let pt = util::xor(&ct, &key);
    Ok(std::str::from_utf8(&pt)?.to_string())
}
