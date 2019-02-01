// http://www.macfreek.nl/memory/Letter_Distribution#Letter_Frequency

const CHARS: [f64; 26] = [
    6.53216702,
    1.25888074,
    2.23367596,
    3.28292310,
    10.26665037,
    1.98306716,
    1.62490441,
    4.97856396,
    5.66844326,
    0.09752181,
    0.56096272,
    3.31754796,
    2.02656783,
    5.71201113,
    6.15957725,
    1.50432428,
    0.08367550,
    4.98790855,
    5.31700534,
    7.51699827,
    2.27579536,
    0.79611644,
    1.70389377,
    0.14092016,
    1.42766662,
    0.05128469,
];

const SPACE: f64 = 18.28846265;

pub fn score(pt: &[u8]) -> f64 {
    let mut score = 0.0;
    for byte in pt {
        if byte.is_ascii_alphabetic() {
            let i = byte.to_ascii_lowercase() - 97;
            score += CHARS[i as usize];
        } else if *byte == 32u8 {
            score += SPACE
        }
    }
    score
}
