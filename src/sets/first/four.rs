use crate::util::*;
use std::io::{BufRead, BufReader};

pub fn run(fname: &str) -> Result<String, Box<std::error::Error>> {
    let file = std::fs::File::open(fname)?;
    let mut high_score = 0.0;
    let mut most_likely = vec![];

    for line in BufReader::new(file).lines() {
        match line {
            Ok(hex_str) => {
                hex::decode(hex_str).and_then(|ct| {
                    let res = brute_char(&ct);
                    if res.1 > high_score {
                        high_score = res.1;
                        most_likely = res.2
                    }
                    Ok(())
                })?;
            }
            Err(e) => eprintln!("{}", e),
        };
    }
    Ok(std::str::from_utf8(&most_likely)?.to_string())
}
