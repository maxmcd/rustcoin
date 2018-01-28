extern crate crypto;
extern crate time;

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
}

fn calculate_hash(index: u32, prev_hash: &String, data: &String, timestamp: u64, nonce: u32) -> String {
    let header_string = format!("{}{}{}{}{}", index, prev_hash, data, timestamp, nonce);
    let mut sha = Sha256::new();
    sha.input_str(&header_string);
    return sha.result_str();
}

fn mine(prev_hash: &String, index: u32) {
    let data = String::from("next block");
    let mut nonce = 0;
    let index = index + 1;
    let timestamp = current_epoch();
    let started = time::now();
    loop {
        let hash = calculate_hash(index, &prev_hash, &data, timestamp, nonce);
        if hash.starts_with("000000") {
            println!("{}", hash);
            let elapsed = time::now() - started;
            print!("{:?}", elapsed);
            break;
        } else {
            nonce += 1;
        }
    }   
}

fn current_epoch() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    return since_the_epoch.as_secs()
}