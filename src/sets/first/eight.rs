use crate::util;
use std::io::{BufRead, BufReader, Error, ErrorKind};

pub fn run(fname: &str) -> Result<String, Box<std::error::Error>> {
    let file = std::fs::File::open(fname)?;
    let mut high_match = 0;
    let mut likely_ecb: Vec<u8> = vec![];

    for (l, line) in BufReader::new(file).lines().enumerate() {
        match line {
            Ok(hex_str) => {
                hex::decode(hex_str).and_then(|ct| {
                    let ct_len = ct.len();
                    let mut block_size = 16;
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
                                if matches > high_match {
                                    high_match = matches;
                                    likely_ecb = ct.to_vec();
                                }
                            }
                        }
                    }
                    Ok(())
                })?;
            }
            Err(e) => eprintln!("{}", e),
        };
    }
    Ok(hex::encode(likely_ecb))
}
