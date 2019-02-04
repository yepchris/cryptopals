use crate::util::*;
use rand::Rng;

fn encryption_oracle(pt: &[u8], unknown: &[u8], key: &[u8]) -> Vec<u8> {
    let mut pt = pt.to_vec();
    pt.append(&mut unknown.to_vec());
    aes_ecb_encrypt(&pad_pkcs7(&pt, 16), &key).unwrap()
}

pub fn run(unknown: &str, key: &str) -> Result<(usize, bool, String), Box<std::error::Error>> {
    let key = base64::decode(&key).unwrap();
    let mut unknown = base64::decode(&unknown).unwrap();
    let mut pt = vec![];

    // get block size and unknown string size
    let mut block_size = 0;
    let mut unk_size = 0;
    let base_ct_len = encryption_oracle(&pt.clone(), &unknown, &key).len();
    let mut i = 0;
    loop {
        i += 1;
        pt.push('A' as u8);
        let ct_len = encryption_oracle(&pt.clone(), &unknown, &key).len();
        if ct_len > base_ct_len {
            block_size = ct_len - base_ct_len;
            unk_size = base_ct_len - i;
            break;
        }
    }

    let mut padding = vec!['A' as u8; block_size];

    // detect ecb mode
    let mut is_ecb = false;
    pt.clear();
    for i in 0..10 {
        pt.append(&mut padding.clone());
        let matches = match_blocks(&encryption_oracle(&pt, &unknown, &key), block_size);
        if matches > 0 {
            is_ecb = true;
            break;
        }
    }

    // decrypt unknown string
    padding = vec!['A' as u8; base_ct_len - 1];
    let mut pt = vec![];
    for i in 0..unk_size {
        let mut oracle_ct =
            &encryption_oracle(&padding.clone(), &unknown, &key)[0..base_ct_len].to_vec();

        // make lookup dictionary for possible ct
        let mut lookup = vec![];
        let mut egg = padding.clone();
        egg.append(&mut pt.clone());
        for j in 0..255 {
            egg.push(j as u8);
            let ct = encryption_oracle(&egg.clone(), &unknown, &key)
                .iter()
                .take(base_ct_len)
                .map(|x| *x)
                .collect::<Vec<u8>>();
            lookup.push((ct, j as u8));
            egg.pop();
        }

        // lookup saved result in dictionary
        match lookup.iter().find(|res| res.0 == *oracle_ct) {
            Some(out) => {
                pt.push(out.1);
                padding.pop();
            }
            None => {}
        }
    }

    Ok((block_size, is_ecb, std::str::from_utf8(&pt)?.to_string()))
}
