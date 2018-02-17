extern crate bigint;
extern crate byteorder;
extern crate core;
extern crate crypto;
extern crate rand;
extern crate rust_base58;
extern crate secp256k1;

mod rc;
use rc::{filesystem, blockdata, network};
use bigint::uint::U256;
use std::{env};

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() > 1 {
        let command = &args[1];
        match command.as_ref() {
            "help" => println!("{}", "commands: new-address, addresses"),
            "new-address" => {
                println!("{}", "Creating new address");
                filesystem::create_new_address();
            }
            "mine-genesis-block" => {
                blockdata::mine_genesis_block();
            }
            "addresses" => {
                println!("{}", "Your wallet addresses:");
                filesystem::list_addresses();
            }
            _ => println!("{}", "invalid arg"),
        }
    } else {
        println!(
            "{}",
            "Starting rustcoin node...\nAvailable commands: \n\tnew-address\n\taddresses");
       network::start_node();
    }
}

fn _difficulty_calculations() {
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