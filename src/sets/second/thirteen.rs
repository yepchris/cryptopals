use crate::util::*;
use rand::Rng;
use std::fmt::Write;

pub fn parse(query: &str) -> String {
    let mut params = vec![];
    query.split('&').for_each(|p| {
        let kv = p.split('=').collect::<Vec<&str>>();
        params.push(kv);
    });
    let mut out = "{".to_string();
    for kv in params {
        write!(&mut out, "\n\t{}: '{}',", kv[0], kv[1]).unwrap();
    }
    // remove trailing comma
    out.pop();

    out.push('\n');
    out.push('}');
    out
}

fn profile_for(email: &str) -> String {
    let mut email = email.replace("&", "");
    email = email.replace("=", "");
    format!("email={}&uid=10&role=user", email)
}

fn encrypt(pt: &[u8], key: &[u8]) -> Vec<u8> {
    aes_ecb_encrypt(&pad_pkcs7(&pt, 16), &key).unwrap()
}

fn decrypt(ct: &[u8], key: &[u8]) -> String {
    let pt = unpad_pkcs7(&aes_ecb_decrypt(&ct, &key).unwrap());
    parse(std::str::from_utf8(&pt).unwrap())
}

pub fn run(input: &str) -> Result<(String, String), Box<std::error::Error>> {
    let key = rand::thread_rng().gen::<[u8; 16]>();

    // get user with banned input
    let to_attacker = encrypt(profile_for(input).as_bytes(), &key);

    // use email from input
    // 32 bytes: email=foos@ball.com&uid=10&role=
    let email = input.split("&").collect::<Vec<&str>>()[0];
    let ct = encrypt(profile_for(email).as_bytes(), &key);
    let first = &ct[0..32];

    // use email to pad until after "role=" from "first"
    // 32 bytes: email=weallliveinayellow@sub.net
    // append "admin" after "role=" block, followed by 16 - admin.len() = 11 as pad bytes
    // 16 bytes: admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
    let ct = encrypt(
        profile_for("weallliveinayellow@sub.netadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")
            .as_bytes(),
        &key,
    );
    let mut second = &ct[32..48];

    // concatenate "email=foos@ball.com&uid=10&role="" with "admin" ciphertext blocks
    let mut admin = first.to_owned();
    admin.append(&mut second.to_owned());

    Ok((decrypt(&to_attacker, &key), decrypt(&admin, &key)))
}
