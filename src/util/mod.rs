use crate::util;
use crypto::{
    aes::{self, KeySize},
    blockmodes, buffer,
    symmetriccipher::{SymmetricCipherError, SynchronousStreamCipher},
};
use rand::{OsRng, Rng, RngCore};
use std::io::{BufReader, BufWriter};
pub mod freq;

pub fn aes_ecb_decrypt(ct: &[u8], key: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut pt: Vec<u8> = vec![0u8; ct.len()];
    aes::ecb_decryptor(aes::KeySize::KeySize128, &key, blockmodes::NoPadding).decrypt(
        &mut buffer::RefReadBuffer::new(&ct),
        &mut buffer::RefWriteBuffer::new(&mut pt),
        true,
    )?;
    Ok(pt.to_vec())
}

pub fn match_blocks(ct: &[u8], block_size: usize) -> usize {
    let ct_len = ct.len();
    let mut chunks = vec![];
    let mut matches = 0;

    for i in (0..ct.len()).step_by(block_size) {
        let j = i + block_size;
        if j >= ct_len {
            break;
        }
        chunks.push(ct[i..j].to_vec());
    }

    for (i, chunk) in chunks.iter().enumerate() {
        for remaining in i + 1..chunks.len() {
            if chunk == &chunks[remaining] {
                matches += 1;
            }
        }
    }
    matches
}

pub fn aes_ecb_encrypt(pt: &[u8], key: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut ct = vec![0u8; pt.len()];
    aes::ecb_encryptor(aes::KeySize::KeySize128, &key, blockmodes::PkcsPadding).encrypt(
        &mut buffer::RefReadBuffer::new(&pt),
        &mut buffer::RefWriteBuffer::new(&mut ct),
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
        ct_block = aes_ecb_encrypt(&input_block, key)?;
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
        pt_block = aes_ecb_decrypt(&ct[i..i + 16], key)?;
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

pub fn mean_hamming(input: &[u8], block_size: usize, block_limit: usize) -> Option<f64> {
    let input_len = input.len();

    let mut chunks = vec![];
    let mut distances = 0;

    for i in (0..input_len).step_by(block_size) {
        let j = i + block_size;
        if j >= input_len || chunks.len() == block_limit {
            break;
        }
        chunks.push(input[i..j].to_vec());
    }

    let num_chunks = chunks.len();
    let mut num_distances = 0;

    // sum distances between all chunks
    for i in 0..num_chunks - 1 {
        for j in 0..num_chunks - 1 {
            if i < j + 1 {
                distances += util::hamming(&chunks[i], &chunks[j + 1]).unwrap();
                num_distances += 1;
            }
        }
    }

    let avg = distances as f64 / num_distances as f64;
    Some(avg / block_size as f64)
}

pub fn hamming(in_1: &[u8], in_2: &[u8]) -> Option<usize> {
    if in_1.len() != in_2.len() {
        None
    } else {
        Some(
            in_1.iter()
                .zip(in_2)
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
