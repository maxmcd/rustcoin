extern crate bigint;
extern crate core;
extern crate crypto;
extern crate rand;
extern crate rust_base58;
extern crate secp256k1;
extern crate time;

use bigint::uint::U256;
use core::ops::Index;
use crypto::digest::Digest;
use crypto::ripemd160::Ripemd160;
use crypto::sha2::Sha256;
use rand::OsRng;
use rust_base58::{ToBase58, FromBase58};
use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::Message;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let (_address, _secrey_key, _public_key) = generate_new_address_and_keys();
    let block = genesis_block();
    let hash = calculate_hash(block);
    println!("{:?}", hash);

    difficulty_calculations();
}

struct Transactions {
    amount: u32,
    transactions: Vec<Transaction>,
}

struct Transaction {
    signature: [u8; 72],
    source: String,   // source is "coinbase" for coinbase transaction
    destination: String, 
    pubkey: PublicKey,
    amount: u32,
}

struct Block {
    index: u32,
    hash: [u8; 32],
    prev_hash: [u8; 32],
    transactions: Transactions,
    nonce: u32,
    timestamp: u32,
}

impl Block {
    // let length = (3*4) + (32);
    fn bytes_to_hash(&self) -> [u8; 44] {
        let index_u8a = transform_u32_to_array_of_u8(self.index);
        let nonce_u8a = transform_u32_to_array_of_u8(self.nonce);
        let timestamp_u8a = transform_u32_to_array_of_u8(self.timestamp);
        let mut out = [0; 44];
        out[..4].clone_from_slice(&index_u8a);
        out[4..8].clone_from_slice(&nonce_u8a);
        out[8..12].clone_from_slice(&timestamp_u8a);
        out[12..44].clone_from_slice(&self.prev_hash);
        out
    }
}

fn generate_transaction_signature(source: &String, destination: &String, sk: &SecretKey, amount: &u32) -> [u8; 72] {
    let amount = transform_u32_to_array_of_u8(*amount);
    let source = source.from_base58().expect("Source not base58");
    let destination = destination.from_base58().expect("destination not base58");
    let bytes = [&source[..], &destination[..], &amount[..]].concat();
    let message = Message::from_slice(&bytes).expect("Failed to create message from slice");
    let secp = secp256k1::Secp256k1::new();
    let result = secp.sign(&message, &sk).expect("Failed to sign");
    let signature = result.serialize_der(&secp);
    let mut out = [0; 72];
    out[0..72].clone_from_slice(&signature);
    out
}

fn transform_u32_to_array_of_u8(x: u32) -> [u8; 4] {
    let b1: u8 = ((x >> 24) & 0xff) as u8;
    let b2: u8 = ((x >> 16) & 0xff) as u8;
    let b3: u8 = ((x >> 8) & 0xff) as u8;
    let b4: u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4];
}

fn create_transaction(sk: SecretKey, pk: PublicKey, source: String, destination: String, amount: u32) -> Transaction {
    let signature = generate_transaction_signature(&source, &destination, &sk, &amount);
    return Transaction {
        pubkey: pk,
        source: source,
        destination: destination,
        amount: amount,
        signature: signature,
    }
}

fn difficulty_calculations() {
    // 0x1d00ffff;
    let difficulty_1_target = [29, 0, 255, 255];
    let diff_second_part: u32 =
        difficulty_1_target[3] | (difficulty_1_target[2] << 8) | (difficulty_1_target[1] << 16);
    // https://en.bitcoin.it/wiki/Difficulty
    // 0x00ffff * 2**(8*(0x1d - 3));
    let mut difficulty = U256::from_big_endian(&[2]);
    let mut difficulty = difficulty.pow(U256::from(8 * (difficulty_1_target[0] - 3)));
    let difficulty = difficulty.saturating_mul(U256::from(diff_second_part));
    let mut out: [u8; 32] = [0; 32];
    difficulty.to_big_endian(&mut out);

    println!("{:?}", out);
    println!("{:?}", difficulty_1_target);
}

fn genesis_block() -> Block {
    let transactions: Vec<Transaction> = Vec::new();
    let transactions =  Transactions {
        amount: 0,
        transactions: transactions,
    };
    Block {
        index: 0,
        prev_hash: [0; 32],
        hash: [0; 32],
        transactions: transactions,
        nonce: 0,
        timestamp: 0,
    }
}

fn generate_new_address_and_keys() -> (String, SecretKey, PublicKey)
{
    // https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    let secp = secp256k1::Secp256k1::new();
    let mut rng = OsRng::new().expect("Failed to create new rng");
    let (secret_key, public_key) = secp.generate_keypair(&mut rng).unwrap();
    let mut result_bytes = sha_256_bytes(secret_key.index(0..32));

    let mut rmd160 = Ripemd160::new();
    rmd160.input(&mut result_bytes);
    let mut rmd160_result = [0; 20];
    rmd160.result(&mut rmd160_result);

    let version = [0];
    let with_version = [&version[0..1], &rmd160_result[0..20]].concat();
    let sha_twice = sha_256_bytes(&sha_256_bytes(&with_version));
    let address = [&with_version[0..21], &sha_twice[0..4]].concat();

    return (address.to_base58(), secret_key, public_key);
}

fn sha_256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.input(bytes);
    let mut out = [0; 32];
    sha.result(&mut out);
    out
}

fn calculate_hash(block: Block) -> [u8; 32] {
    sha_256_bytes(&block.bytes_to_hash())
}

// fn mine(prev_hash: [u8; 32], index: u32) {
//     let data = String::from("next block");
//     let mut nonce = 0;
//     let index = index + 1;
//     let timestamp = current_epoch();
//     loop {
//         let hash = calculate_hash(index, &prev_hash, &data, timestamp, nonce);
//         if hash.starts_with("0") {
//             println!("{:?}", hash);
//             break;
//         } else {
//             nonce += 1;
//         }
//     }
// }

// fn current_epoch() -> u64 {
//     let start = SystemTime::now();
//     let since_the_epoch = start
//         .duration_since(UNIX_EPOCH)
//         .expect("Time went backwards");
//     return since_the_epoch.as_secs();
// }
