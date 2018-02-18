use rc::blockdata::{Address, Block, Wallet};
use rc::byteorder::ByteOrder;
use rc::byteorder;
use rc::constants::U32_SIZE;
use rc::encode::Encodable;

use std::io::{Read, Write};
use std::{env, fs};
use std;

pub fn rustcoin_dir() -> std::path::PathBuf {
    let home_dir = env::home_dir().unwrap();
    home_dir.join(".rustcoin")
}

pub fn create_data_dir() -> (fs::File, fs::File) {
    let rustcoin_dir = rustcoin_dir();
    match fs::read_dir(&rustcoin_dir) {
        Ok(_) => {}
        Err(_) => {
            let _result = fs::create_dir(&rustcoin_dir);
        }
    };
    let wallet = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&rustcoin_dir.join("wallet.dat"))
        .unwrap();
    let blockdata = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&rustcoin_dir.join("blockdata.dat"))
        .unwrap();
    return (wallet, blockdata);
}

pub fn fetch_blocks() -> Vec<Block> {
    let (_, mut blockdata) = create_data_dir();
    let mut length = [0u8; U32_SIZE];
    let blocks: Vec<Block> = match blockdata.read(&mut length) {
        Ok(_) => {
            let len = byteorder::BigEndian::read_u32(&length);
            let mut blockbytes: Vec<u8> = Vec::new();
            blockdata.read_to_end(&mut blockbytes).unwrap();
            let mut blocks: Vec<Block> = Vec::new();
            for _ in 0..len {
                let block = Block::deserialize(&mut blockbytes);
                blocks.push(block);
            }
            blocks
        }
        Err(_) => Vec::new(),
    };
    blocks
}

pub fn write_blocks(blocks: &Vec<Block>) {
    let mut blockdata = fs::OpenOptions::new()
        .write(true)
        .open(&rustcoin_dir().join("blockdata.dat"))
        .unwrap();
    let mut to_write: Vec<u8> = Vec::new();
    (blocks.len() as u32).serialize(&mut to_write);
    for block in blocks {
        to_write.extend(block.serialize());
    }
    blockdata.write_all(&to_write).unwrap();
    blockdata.sync_data().unwrap();
}

pub fn fetch_wallet() -> Wallet {
    let (mut wallet_file, _) = create_data_dir();
    let mut version = [0u8; 2];
    let wallet = match wallet_file.read(&mut version) {
        Ok(_) => {
            let mut len = [0u8];
            // maximum 255 addresses
            wallet_file.read(&mut len).unwrap();
            let mut addresses: Vec<Address> = Vec::new();
            for _ in 0..len[0] {
                let mut address = [0u8; (32 + 64)];
                wallet_file.read(&mut address).unwrap();
                let mut sk = [0; 32];
                sk[..].clone_from_slice(&address[..32]);
                let mut pk = [0; 64];
                pk[..].clone_from_slice(&address[32..(64 + 32)]);
                addresses.push(Address { sk: sk, pk: pk })
            }
            Wallet {
                addresses: addresses,
                version: version,
            }
        }
        Err(_) => {
            // TODO: return unexpected errors
            let mut addresses: Vec<Address> = Vec::new();
            Wallet {
                version: [0u8, 1],
                addresses: addresses,
            }
        }
    };
    wallet
}

pub fn create_new_address() {
    let mut wallet = fetch_wallet();
    let address = Address::new();
    println!("{}", address.address());
    wallet.addresses.push(address);
    // Using the same file we've opened writes data to the disk that
    // is partially updated. This fixes that, find out why?
    // maybe the file just needs to be flushed before writing?
    let mut wallet_file = fs::OpenOptions::new()
        .write(true)
        .open(&rustcoin_dir().join("wallet.dat"))
        .unwrap();
    wallet_file.write_all(&wallet.serialize()).unwrap();
    wallet_file.sync_data().unwrap();
}

pub fn list_addresses() {
    let wallet = fetch_wallet();
    for address in wallet.addresses {
        println!("{}", address.address());
    }
}
