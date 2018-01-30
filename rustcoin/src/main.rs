extern crate crypto;
extern crate rand;
extern crate secp256k1;
extern crate time;

use rand::OsRng;
use std::time::{SystemTime, UNIX_EPOCH};
use crypto::digest::Digest;
use crypto::sha2::Sha256;

fn main() {
    let index = 0;
    let prev_hash = String::from("");
    let data = String::from("nothing for now");
    let timestamp = current_epoch();
    let nonce = 0;
    let hash = calculate_hash(index, &prev_hash, &data, timestamp, nonce);
    println!("{}", hash);
    mine(&hash, index);
    let secp = secp256k1::Secp256k1::new();
    let mut rng = OsRng::new().expect("Failed to create new rng");
    let (secret_key, public_key) = secp.generate_keypair(&mut rng).unwrap();
    println!("{:?}", secret_key);
    println!("{:?}", public_key);
}

fn calculate_hash(
    index: u32,
    prev_hash: &String,
    data: &String,
    timestamp: u64,
    nonce: u32,
) -> String {
    let header_string = format!("{}{}{}{}{}", index, prev_hash, data, timestamp, nonce);
    let mut sha = Sha256::new();
    sha.input_str(&header_string);
    let result = sha.result_str();

    let mut _result_bytes = [0; 32];
    sha.result(&mut _result_bytes);

    return result;
}

fn mine(prev_hash: &String, index: u32) {
    let data = String::from("next block");
    let mut nonce = 0;
    let index = index + 1;
    let timestamp = current_epoch();
    loop {
        let hash = calculate_hash(index, &prev_hash, &data, timestamp, nonce);
        if hash.starts_with("0") {
            println!("{:?}", hash);
            break;
        } else {
            nonce += 1;
        }
    }
}

fn current_epoch() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    return since_the_epoch.as_secs();
}
