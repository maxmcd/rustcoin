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
use rust_base58::{FromBase58, ToBase58};
use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::Message;
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
        println!("{:?}", "Run rustcoin without args, starting node.");
        let _block = mine_genesis_block();
    }
}

struct Wallet {
    version: [u8; 2],
    addresses: Vec<Address>,
}

struct Transactions {
    amount: u64,
    transactions: Vec<Transaction>,
}

struct Transaction {
    signature: [u8; 64],
    source: [u8; 25], // source is coinbase() for coinbase transaction
    destination: [u8; 25],
    pk: [u8; 33],
    amount: u64,
    nonce_overflow: u32,
}

struct Block {
    version: [u8; 2],
    index: u32,
    prev_hash: [u8; 32],
    transactions: Transactions,
    nonce: u32,
    timestamp: u64,
    merkle_root: [u8; 32],
}

struct Address {
    sk: [u8; 32],
    pk: [u8; 33],
    address: [u8; 25],
}

fn coinbase() -> [u8; 25] {
    // "coinbase"
    // let coinbasehex = 0x636f696e62617365
    let mut out = [0; 25];
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
        Ok(dir) => {}
        Err(error) => {
            fs::create_dir(&rustcoin_dir);
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
        let mut rng = OsRng::new().expect("Failed to create new rng");
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

    fn create_transaction(
        &self,
        amount: u64,
        destination: [u8; 25],
        is_coinbase: bool,
    ) -> Transaction {
        let source = if is_coinbase {
            coinbase()
        } else {
            self.address
        };
        let mut transaction = Transaction {
            signature: [0; 64],
            source: source,
            destination: destination,
            pk: self.pk,
            amount: amount,
            nonce_overflow: 0,
        };
        transaction.generate_transaction_signature(&self.sk);
        transaction
    }
}

impl Block {
    // let length = (3*4) + (32);
    fn bytes_to_hash(&self) -> [u8; (2 + 4 + 32 + 4 + 8 + 32 + 8)] {
        let index_u8a = transform_u32_to_array_of_u8(self.index);
        let nonce_u8a = transform_u32_to_array_of_u8(self.nonce);
        let timestamp_u8a = transform_u64_to_array_of_u8(self.timestamp);
        let amount_u8a = transform_u64_to_array_of_u8(self.transactions.amount);
        let mut out = [0; (2 + 4 + 32 + 4 + 8 + 32 + 8)];
        let bytes = [
            &self.version[..],
            &index_u8a[..],
            &self.prev_hash[..],
            &nonce_u8a,
            &timestamp_u8a,
            &self.merkle_root,
            &amount_u8a,
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

impl Transaction {
    fn generate_transaction_signature(&mut self, sk: &[u8; 32]) {
        let secp = secp256k1::Secp256k1::new();
        let sk = SecretKey::from_slice(&secp, sk).unwrap();
        let amount = transform_u64_to_array_of_u8(self.amount);
        let bytes =
            [&self.source[..], &self.destination[..], &amount[..]].concat();
        let bytes = sha_256_bytes(&bytes);
        let message = Message::from_slice(&bytes).unwrap();
        let result = secp.sign(&message, &sk).expect("Failed to sign");
        let signature = result.serialize_compact(&secp);
        &self.signature[0..64].clone_from_slice(&signature);
    }

    fn serialize(&self) -> [u8; (64 + 25 + 25 + 33 + 8 + 4)] {
        let mut out = [0; (64 + 25 + 25 + 33 + 8 + 4)];
        let bytes = [
            &self.signature[..],
            &self.source[..],
            &self.destination[..],
            &self.pk[..],
            &transform_u64_to_array_of_u8(self.amount),
            &transform_u32_to_array_of_u8(self.nonce_overflow),
        ].concat();

        out[..].clone_from_slice(&bytes[..]);
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
    let mut transactions: Vec<Transaction> = Vec::new();
    let address = Address::new();
    let transaction =
        address.create_transaction(5000000000, address.address, true);
    transactions.push(transaction);
    let transactions = Transactions {
        amount: 5000000000,
        transactions: transactions,
    };

    // one transaction, so just double sha it
    let merkle_root = sha_256_bytes(&sha_256_bytes(&transactions.transactions
        [0]
        .serialize()));

    let mut block = Block {
        index: 0,
        version: [0; 2],
        merkle_root: merkle_root,
        prev_hash: [0; 32],
        transactions: transactions,
        nonce: 0,
        timestamp: current_epoch(),
    };
    loop {
        let hash = block.hash();
        if hash_is_valid_with_current_difficulty(hash) {
            println!("hash {:?}", hash);
            println!("nonce {:?}", block.nonce);
            println!("ts {:?}", block.timestamp);
            let transaction = &block.transactions.transactions[0];
            println!("pk1 {:?}", &transaction.pk[..32]);
            println!("pk2 {:?}", &transaction.pk[32..]);
            println!("sig1 {:?}", &transaction.signature[..32]);
            println!("sig2 {:?}", &transaction.signature[32..]);
            println!("address {:?}", address.address);
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
