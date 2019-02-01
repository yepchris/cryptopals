use crate::util::*;

pub fn run(input: &str) -> Result<String, Box<std::error::Error>> {
    let ct = hex::decode(input)?;
    let most_likely = brute_char(&ct);
    Ok(std::str::from_utf8(&most_likely.2)?.to_string())
}
