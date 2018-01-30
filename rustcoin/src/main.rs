extern crate crypto;
extern crate rand;
extern crate secp256k1;
extern crate time;
extern crate core;
extern crate rust_base58;


use rand::OsRng;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use crypto::ripemd160::Ripemd160;
use core::ops::Index;
use rust_base58::{ToBase58};

fn main() {
    let index = 0;
    let prev_hash = String::from("");
    let data = String::from("nothing for now");
    let timestamp = current_epoch();
    let nonce = 0;
    let hash = calculate_hash(index, &prev_hash, &data, timestamp, nonce);
    println!("{}", hash);
    mine(&hash, index);
    generate_new_address_and_keys()
}

fn generate_new_address_and_keys() {
    // https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    let secp = secp256k1::Secp256k1::new();
    let mut rng = OsRng::new().expect("Failed to create new rng");
    let (secret_key, public_key) = secp.generate_keypair(&mut rng).unwrap();
    println!("{:?}", secret_key);
    println!("{:?}", public_key);

    let mut result_bytes = sha_256_bytes(secret_key.index(0..32));
    println!("{:?}", "sha of public key");
    println!("{:?}", result_bytes);

    let mut rmd160 = Ripemd160::new();
    rmd160.input(&mut result_bytes);
    let mut rmd160_result = [0; 20];
    rmd160.result(&mut rmd160_result);
    println!("{:?}", "rmd160 of sha of public key");
    println!("{:?}", rmd160_result);

    let version = [0];
    let with_version = [&version[0..1], &rmd160_result[0..20]].concat();
    println!("{:?}", with_version);

    let sha_twice = sha_256_bytes(&sha_256_bytes(&with_version));
    println!("{:?}", sha_twice);

    let address = [&with_version[0..21], &sha_twice[0..4]].concat();
    println!("{:?}", address);

    println!("{:?}", &address.to_base58());
}

fn sha_256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.input(bytes);
    let mut out = [0; 32];
    sha.result(&mut out);
    out
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
