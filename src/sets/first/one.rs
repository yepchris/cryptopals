pub fn run(input: &str) -> Result<String, Box<std::error::Error>> {
    let bytes = hex::decode(input)?;
    Ok(base64::encode(&bytes))
}
