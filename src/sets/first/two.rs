use crate::util;

pub fn run(input_1: &str, input_2: &str) -> String {
    hex::encode(util::xor(
        &hex::decode(input_1).unwrap(),
        &hex::decode(input_2).unwrap(),
    ))
}
