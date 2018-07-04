extern crate bigint;
extern crate byteorder;
extern crate core;
extern crate crypto;
extern crate rand;
extern crate rust_base58;
extern crate secp256k1;
#[macro_use]
extern crate lazy_static;

mod blockdata;
mod constants;
mod encode;
mod filesystem;
mod network;
mod util;

use std::env;

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
