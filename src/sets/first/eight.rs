use crate::util::*;
use std::io::{BufRead, BufReader, Error, ErrorKind};

pub fn run(fname: &str) -> Result<String, Box<std::error::Error>> {
    let file = std::fs::File::open(fname)?;
    let mut high_match = 0;
    let mut likely_ecb: Vec<u8> = vec![];

    for (l, line) in BufReader::new(file).lines().enumerate() {
        match line {
            Ok(hex_str) => {
                hex::decode(hex_str).and_then(|ct| {
                    let matches = match_blocks(&ct, 16);
                    
                    if matches > high_match {
                        high_match = matches;
                        likely_ecb = ct.to_vec();
                    }

                    Ok(())
                })?;
            }
            Err(e) => eprintln!("{}", e),
        };
    }
    Ok(hex::encode(likely_ecb))
}
