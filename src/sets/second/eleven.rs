use crate::util::*;
use rand::Rng;

fn cbc(pt: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = rand::thread_rng().gen::<[u8; 16]>();
    aes_cbc_encrypt(&pt, &key, &iv).unwrap()
}

fn ecb(pt: &[u8], key: &[u8]) -> Vec<u8> {
    aes_ecb_encrypt(&pt, &key).unwrap()
}

fn prepare(pt: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    // 5-10 random bytes
    let prepend = rng.gen_range(5, 11);
    let append = rng.gen_range(5, 11);

    let mut out = vec![];

    for i in 0..prepend {
        out.push(i as u8)
    }
    for b in pt {
        out.push(*b)
    }
    for i in 0..append {
        out.push(i as u8)
    }

    pad_pkcs7(&out, 16)
}

fn encryption_oracle(pt: &[u8], cbc_or_not: bool) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let key = rng.gen::<[u8; 16]>();
    let pt_prepared = prepare(&pt);

    if cbc_or_not {
        cbc(&pt_prepared, &key)
    } else {
        ecb(&pt_prepared, &key)
    }
}

pub fn id_algo(ct: &[u8]) -> bool {
    let mut is_cbc = true;
    let matches = match_blocks(&ct, 16);

    if matches > 0 {
        is_cbc = false
    }

    is_cbc
}

pub fn run(b64: &str, cbc_or_not: bool) -> bool {
    let pt = base64::decode(&b64).unwrap();
    let ct = encryption_oracle(&pt, cbc_or_not);
    id_algo(&ct)
}
