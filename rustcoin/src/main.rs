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
use rust_base58::ToBase58;
use secp256k1::Message;
use secp256k1::key::{PublicKey, SecretKey};
use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() > 1 {
        let command = &args[1];
        match command.as_ref() {
            "help" => println!("{}", "commands: new-address, addresses"),
            "new-address" => {
                println!("{}", "new address");
                create_new_address();
            }
            "addresses" => println!("{}", "addresses"),
            _ => println!("{}", "invalid arg"),
        }
    } else {
        println!(
            "{:?}",
            "Starting rustcoin node...\nAvailable commands: \n\tnew-address\n\taddresses");
        let _block = mine_genesis_block();
    }
}

struct Wallet {
    version: [u8; 2],
    addresses: Vec<Address>,
}

struct Transaction {
    tx_in: Vec<TxIn>,
    tx_out: Vec<TxOut>,
}

struct TxIn {
    tx_index: u32,
    previous_tx: [u8; 32], // hash is coinbase() for coinbase transaction
    amount: u64,
    pk: [u8; 33],
    signature: [u8; 64],
}

struct TxOut {
    destination: [u8; 33],
    amount: u64,
}

struct Block {
    version: [u8; 2],
    index: u32,
    prev_hash: [u8; 32],
    transactions: Vec<Transaction>,
    nonce: u64,
    timestamp: u64,
    merkle_root: [u8; 32],
}

struct Address {
    sk: [u8; 32],
    pk: [u8; 33],
    address: [u8; 25],
}

fn coinbase() -> [u8; 32] {
    // "coinbase"
    // let coinbasehex = 0x636f696e62617365
    let mut out = [0; 32];
    out[..8].clone_from_slice(
        &[0x63, 0x6f, 0x69, 0x6e, 0x62, 0x61, 0x73, 0x65][..],
    );
    out
}

fn rustcoin_dir() -> std::path::PathBuf {
    let home_dir = env::home_dir().unwrap();
    home_dir.join(".rustcoin")
}

fn create_data_dir() -> (fs::File, fs::File) {
    let rustcoin_dir = rustcoin_dir();
    match fs::read_dir(&rustcoin_dir) {
        Ok(_) => {}
        Err(_) => {
            let _result = fs::create_dir(&rustcoin_dir);
        }
    };
    let wallet = fs::File::create(rustcoin_dir.join("wallet.dat")).unwrap();
    let blockdata =
        fs::File::create(rustcoin_dir.join("blockdata.dat")).unwrap();
    return (wallet, blockdata);
}

fn create_new_address() {
    let _address = Address::new();
    create_data_dir();
}

impl Address {
    fn new() -> Address {
        // https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
        let secp = secp256k1::Secp256k1::new();
        let mut rng = OsRng::new().unwrap();
        let (secret_key, public_key) = secp.generate_keypair(&mut rng).unwrap();
        let mut result_bytes = sha_256_bytes(secret_key.index(0..32));

        let mut rmd160 = Ripemd160::new();
        rmd160.input(&mut result_bytes);
        let mut rmd160_result = [0; 20];
        rmd160.result(&mut rmd160_result);

        let version = [0];
        let with_version = [&version[..1], &rmd160_result[..20]].concat();
        let sha_twice = sha_256_bytes(&sha_256_bytes(&with_version));
        let mut address = [0; 25];
        address[..21].clone_from_slice(&with_version[..21]);
        address[21..25].clone_from_slice(&sha_twice[..4]);

        // secp256k1::constants::SECRET_KEY_SIZE
        let mut sk = [0; 32];
        sk[..32].clone_from_slice(&secret_key[..32]);
        Address {
            address: address,
            pk: public_key.serialize(),
            sk: sk,
        }
    }

    fn serialize(&self) -> [u8; (32 + 33 + 25)] {
        let mut out = [0; (32 + 33 + 25)];
        let bytes = [&self.sk[..], &self.pk[..], &self.address[..]].concat();
        out[..].clone_from_slice(&bytes);
        out
    }
}

impl Block {
    // let length = (3*4) + (32);
    fn bytes_to_hash(&self) -> [u8; (2 + 4 + 32 + 8 + 8 + 32)] {
        let index_u8a = transform_u32_to_array_of_u8(self.index);
        let nonce_u8a = transform_u64_to_array_of_u8(self.nonce);
        let timestamp_u8a = transform_u64_to_array_of_u8(self.timestamp);
        let mut out = [0; (2 + 4 + 32 + 8 + 8 + 32)];
        let bytes = [
            &self.version[..],
            &index_u8a[..],
            &self.prev_hash[..],
            &nonce_u8a,
            &timestamp_u8a,
            &self.merkle_root,
        ].concat();
        out[..].clone_from_slice(&bytes[..]);
        out
    }

    fn calculate_merkel_root(&self) -> [u8; 32] {
        let out = [0; 32];
        out
    }

    fn hash(&self) -> [u8; 32] {
        sha_256_bytes(&self.bytes_to_hash())
    }
}

impl TxIn {}

// fn merkle_root(transactions: ) {
//     let length = transactions.len();
//     // has to be a power of 2?
//     // clone one remaining item to fill leaves?
// }

impl TxIn {
    fn serialize(&self) -> Vec<u8> {
        [
            &transform_u32_to_array_of_u8(self.tx_index)[..],
            &self.previous_tx[..],
            &transform_u64_to_array_of_u8(self.amount)[..],
            &self.pk[..],
            &self.signature[..],
        ].concat()
    }

    fn sign(&mut self, sk: &[u8; 32]) {
        let secp = secp256k1::Secp256k1::new();
        let sk = SecretKey::from_slice(&secp, sk).unwrap();
        let bytes = self.serialize();
        let bytes = &bytes[..(bytes.len() - 64)]; // remove empty sig
        let bytes = sha_256_bytes(&bytes);
        let message = Message::from_slice(&bytes).unwrap();
        let result = secp.sign(&message, &sk).expect("Failed to sign");
        let signature = result.serialize_compact(&secp);
        &self.signature[..].clone_from_slice(&signature);
    }
}

impl TxOut {
    fn serialize(&self) -> Vec<u8> {
        [
            &self.destination[..],
            &transform_u64_to_array_of_u8(self.amount)[..],
        ].concat()
    }
}

impl Transaction {
    fn serialize(&self) -> Vec<u8> {
        let in_len = transform_u32_to_array_of_u8(self.tx_in.len() as u32);
        let out_len = transform_u32_to_array_of_u8(self.tx_in.len() as u32);
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&in_len);
        for tx_out in &self.tx_out {
            out.append(&mut tx_out.serialize())
        }
        out.extend_from_slice(&out_len);
        for tx_in in &self.tx_in {
            out.append(&mut tx_in.serialize())
        }
        out
    }
}

fn transform_u32_to_array_of_u8(x: u32) -> [u8; 4] {
    let b1: u8 = ((x >> 24) & 0xff) as u8;
    let b2: u8 = ((x >> 16) & 0xff) as u8;
    let b3: u8 = ((x >> 8) & 0xff) as u8;
    let b4: u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4];
}

fn transform_u64_to_array_of_u8(x: u64) -> [u8; 8] {
    let b1: u8 = ((x >> 54) & 0xff) as u8;
    let b2: u8 = ((x >> 48) & 0xff) as u8;
    let b3: u8 = ((x >> 40) & 0xff) as u8;
    let b4: u8 = ((x >> 32) & 0xff) as u8;
    let b5: u8 = ((x >> 24) & 0xff) as u8;
    let b6: u8 = ((x >> 16) & 0xff) as u8;
    let b7: u8 = ((x >> 8) & 0xff) as u8;
    let b8: u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4, b5, b6, b7, b8];
}

fn create_coinbase_transaction(destination: [u8; 33]) -> Transaction {
    let tx_in = TxIn {
        previous_tx: coinbase(),
        tx_index: 0,
        amount: 5000000000,
        pk: [0; 33],
        signature: [0; 64],
    };
    let tx_out = TxOut {
        destination: destination,
        amount: 5000000000,
    };
    Transaction {
        tx_in: vec![tx_in],
        tx_out: vec![tx_out],
    }
}

fn difficulty_calculations() {
    // 0x1d00ffff;
    let difficulty_1_target = [29, 0, 255, 255];
    let diff_second_part: u32 = difficulty_1_target[3]
        | (difficulty_1_target[2] << 8)
        | (difficulty_1_target[1] << 16);
    // https://en.bitcoin.it/wiki/Difficulty
    // 0x00ffff * 2**(8*(0x1d - 3));
    let difficulty = U256::from_big_endian(&[2]);
    let difficulty =
        difficulty.pow(U256::from(8 * (difficulty_1_target[0] - 3)));
    let difficulty = difficulty.saturating_mul(U256::from(diff_second_part));
    let mut out: [u8; 32] = [0; 32];
    difficulty.to_big_endian(&mut out);

    let mut valid_hash = [0; 32];
    let valid_hash_u256 = U256::from_big_endian(&valid_hash);
    println!("{:?}", valid_hash_u256 < difficulty);

    valid_hash[2] = 1;
    let valid_hash_u256 = U256::from_big_endian(&valid_hash);
    println!("{:?}", valid_hash_u256 < difficulty);

    println!("{:?}", out);
    println!("{:?}", difficulty_1_target);
}

fn hash_is_valid_with_current_difficulty(hash: [u8; 32]) -> bool {
    let hash_u256 = U256::from_big_endian(&hash);
    let difficulty = [
        0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    // let difficulty = [
    //     0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // ];
    let difficulty = U256::from_big_endian(&difficulty);
    return hash_u256 < difficulty;
}

fn mine_genesis_block() -> Block {
    let address = Address::new();
    let transaction = create_coinbase_transaction(address.pk);

    // one transaction, so just double sha it
    let merkle_root = [0; 32];

    let mut block = Block {
        index: 0,
        version: [0; 2],
        merkle_root: merkle_root,
        prev_hash: [0; 32],
        transactions: vec![transaction],
        nonce: 0,
        timestamp: current_epoch(),
    };
    loop {
        let hash = block.hash();
        if hash_is_valid_with_current_difficulty(hash) {
            println!("hash {:?}", hash);
            println!("nonce {:?}", block.nonce);
            println!("ts {:?}", block.timestamp);
            let tx_out = &block.transactions[0].tx_out[0];
            println!("pk1 {:?}", &tx_out.destination[..32]);
            println!("pk2 {:?}", &tx_out.destination[32..]);
            break;
        };
        block.nonce += 1
    }

    block
}

fn sha_256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.input(bytes);
    let mut out = [0; 32];
    sha.result(&mut out);
    out
}

fn current_epoch() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    return since_the_epoch.as_secs();
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
