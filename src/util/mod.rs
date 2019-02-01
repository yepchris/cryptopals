use crate::util;
use crypto::{
    aes::{self, KeySize},
    blockmodes, buffer,
    symmetriccipher::{SymmetricCipherError, SynchronousStreamCipher},
};
use rand::{OsRng, Rng, RngCore};
use std::io::{BufReader, BufWriter};
pub mod freq;

pub fn aes_ecb_decrypt(
    ct: &[u8],
    pt: &mut [u8],
    key: &[u8],
) -> Result<Vec<u8>, SymmetricCipherError> {
    aes::ecb_decryptor(aes::KeySize::KeySize128, &key, blockmodes::NoPadding).decrypt(
        &mut buffer::RefReadBuffer::new(&ct),
        &mut buffer::RefWriteBuffer::new(pt),
        true,
    )?;
    Ok(pt.to_vec())
}

pub fn aes_ecb_encrypt(
    pt: &[u8],
    ct: &mut [u8],
    key: &[u8],
) -> Result<Vec<u8>, SymmetricCipherError> {
    aes::ecb_encryptor(aes::KeySize::KeySize128, &key, blockmodes::PkcsPadding).encrypt(
        &mut buffer::RefReadBuffer::new(&pt),
        &mut buffer::RefWriteBuffer::new(ct),
        true,
    )?;
    Ok(ct.to_vec())
}

pub fn aes_cbc_encrypt(pt: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut ct_block = vec![0u8; 16];
    let mut prev_block = iv;
    let mut ct = vec![];

    for i in (0..pt.len()).step_by(16) {
        let pt_block = pt[i..i + 16].to_vec();
        let input_block = xor(&pt_block, &prev_block);
        aes_ecb_encrypt(&input_block, &mut ct_block, key)?;
        ct.append(&mut ct_block.to_owned());
        prev_block = &ct_block;
    }
    Ok(ct)
}

pub fn aes_cbc_decrypt(ct: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut pt_block = vec![0u8; 16];
    let mut ct_block = vec![0u8; 16];
    let mut prev_block = iv;
    let mut pt = vec![];

    for i in (0..ct.len()).step_by(16) {
        aes_ecb_decrypt(&ct[i..i + 16], &mut pt_block, key)?;
        let output_block = xor(&pt_block, &prev_block);
        pt.append(&mut output_block.to_owned());
        prev_block = &ct[i..i + 16];
    }
    Ok(pt)
}

pub fn brute_char(chunk: &[u8]) -> (u8, f64, Vec<u8>) {
    let mut most_likely: (u8, f64, Vec<u8>) = (0u8, 0.0f64, vec![]);
    for byte in 0..255 as u8 {
        let pt = util::xor(chunk, &[byte]);
        let score = util::freq::score(&pt.clone());
        if score > most_likely.1 {
            most_likely.0 = byte;
            most_likely.1 = score;
            most_likely.2 = pt;
        }
    }
    most_likely
}

pub fn hamming(str_1: &[u8], str_2: &[u8]) -> Option<usize> {
    if str_1.len() != str_2.len() {
        None
    } else {
        Some(
            str_1
                .iter()
                .zip(str_2)
                .fold(0, |a, (b, c)| a + (*b ^ *c).count_ones() as usize),
        )
    }
}

pub fn pad_pkcs7(input: &[u8], block_len: u8) -> Vec<u8> {
    let mut padded = input.to_vec();

    let remainder: u8 = (input.len() % block_len as usize) as u8;
    if remainder != 0 {
        let pad = block_len - remainder;

        for i in 0..pad as usize {
            padded.push(pad.clone());
        }
        padded
    } else {
        input.to_vec()
    }
}

pub fn transpose(ct: &[u8], keysize: usize) -> Vec<Vec<u8>> {
    let mut chunks = vec![];
    let ct_len = ct.len();

    for i in 0..ct_len / keysize {
        chunks.push(ct[keysize * i..keysize * (i + 1)].to_vec());
    }
    let offset = ct_len - (ct_len % keysize);
    chunks.push(ct[offset..].to_vec());

    let mut transposed = vec![];

    for i in 0..keysize {
        let mut t = vec![];
        for chunk in chunks.iter() {
            let l = chunk.len();
            if l < i {
                continue;
            }
            t.push(chunk[i % l]);
        }
        transposed.push(t);
    }
    transposed
}

pub fn xor(input_1: &[u8], input_2: &[u8]) -> Vec<u8> {
    let l = input_2.len();
    let mut result: Vec<u8> = vec![];
    for (i, byte) in input_1.iter().enumerate() {
        result.push(byte ^ input_2[i % l]);
    }
    result
}

/*
mod tests {
    #[test]
    fn xor() {
        assert_eq!(
        super::xor(&[0x01, 0x02, 0x03, 0x02, 0x00],
            &[0x01, 0x02, 0x04]
        ).unwrap(), &[0x00, 0x00, 0x07, 0x03, 0x02]);
    }
}
*/
