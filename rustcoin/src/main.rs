extern crate bigint;
extern crate byteorder;
extern crate core;
extern crate crypto;
extern crate rand;
extern crate rust_base58;
extern crate secp256k1;

use bigint::uint::U256;
use byteorder::ByteOrder;
use crypto::digest::Digest;
use crypto::ripemd160::Ripemd160;
use crypto::sha2::Sha256;
use rand::OsRng;
use rust_base58::ToBase58;
use secp256k1::key::{PublicKey, SecretKey};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, net, thread, time};

const MAGIC_NUMBER_SIZE: usize = 4;
const COMMAND_SIZE: usize = 12;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() > 1 {
        let command = &args[1];
        match command.as_ref() {
            "help" => println!("{}", "commands: new-address, addresses"),
            "new-address" => {
                println!("{}", "Creating new address");
                create_new_address();
            }
            "addresses" => {
                println!("{}", "Your wallet addresses:");
                list_addresses();
            }
            _ => println!("{}", "invalid arg"),
        }
    } else {
        println!(
            "{}",
            "Starting rustcoin node...\nAvailable commands: \n\tnew-address\n\taddresses");
        start_node();
        // let _block = mine_genesis_block();
    }
}

fn start_node() {
    let port = match env::var("PORT") {
        Ok(port) => port,
        Err(_) => "8333".to_string(),
    };
    let known_node = "127.0.0.1:8333";
    let active_nodes_arc: Arc<RwLock<HashMap<net::SocketAddr, u64>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let active_nodes_rw = Arc::clone(&active_nodes_arc);

    if port != "8333".to_string() {
        {
            let mut active_nodes = active_nodes_rw.write().unwrap();

            active_nodes.insert(
                known_node.to_socket_addrs().unwrap().next().unwrap(),
                0,
            );
        }
    }

    let socket = net::UdpSocket::bind(format!("127.0.0.1:{}", port)).unwrap();

    println!("Broadcasting on {}", port);

    let pong = Message {
        payload: Vec::new(),
        command: [0x70, 0x6f, 0x6e, 0x67, 0, 0, 0, 0, 0, 0, 0, 0],
    };
    let getaddr = Message {
        payload: Vec::new(),
        command: [0x67, 0x65, 0x74, 0x61, 0x64, 0x64, 0x72, 0, 0, 0, 0, 0],
    };
    // let (message_sender, message_receiver) = mpsc::channel::<ToSend>();

    {
        let active_nodes = active_nodes_rw.read().unwrap();
        for (node, _) in active_nodes.iter() {
            socket.send_to(&getaddr.serialize(), &node).unwrap();
            println!("Sent getaddr to {}", &node);
        }
    }

    let send_socket = socket.try_clone().unwrap();
    // // Message sender
    // thread::spawn(move || {

    // });

    // Scheduled task sender
    thread::spawn(move || {
        let active_nodes_rw = Arc::clone(&active_nodes_arc);
        let ping = Message {
            payload: Vec::new(),
            command: [0x70, 0x69, 0x6e, 0x67, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        loop {
            thread::sleep(time::Duration::from_millis(1000));
            let active_nodes = active_nodes_rw.read().unwrap();
            for (node, _) in active_nodes.iter() {
                println!("Sent ping to {}", &node);
                send_socket.send_to(&ping.serialize(), node).unwrap();
            }
        }
    });

    // Message receiver
    loop {
        // 2mb, largest message size
        let mut buf = [0; 2_000_000];
        let (_amt, src) = socket.recv_from(&mut buf).unwrap();
        {
            let mut active_nodes = active_nodes_rw.write().unwrap();
            active_nodes.insert(src, current_epoch());
        }
        let (command, payload) = Message::deserialize(&buf);
        let command = String::from_utf8_lossy(command);
        println!("Command \"{}\" from {}", command, src);
        match command.as_ref() {
            "ping\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}" => {
                socket.send_to(&pong.serialize(), src).unwrap();
            }
            "getaddr\u{0}\u{0}\u{0}\u{0}\u{0}" => {
                let active_nodes = active_nodes_rw.read().unwrap();
                let addr = Addr::serialize(&active_nodes);
                socket.send_to(&addr.serialize(), src).unwrap();
            }
            "addr\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}" => {
                {
                    let mut active_nodes = active_nodes_rw.write().unwrap();
                    let addresses = Addr::deserialize(&payload);
                    for address in &addresses {
                        // Don't add me
                        if socket.local_addr().unwrap() != address.address {
                            // TODO: take the freshest timestamp
                            active_nodes.insert(address.address, address.ts);
                        }
                    }
                    println!("{:?}", &buf[16..(32 + 16)]);
                }
            }
            "pong\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}" => {}
            &_ => {
                println!("No match for command {}", command);
            }
        }
    }
}

struct Message {
    command: [u8; 12],
    payload: Vec<u8>,
}

struct Addr {
    address: net::SocketAddr,
    ts: u64,
}

impl Addr {
    fn serialize(active_nodes: &HashMap<net::SocketAddr, u64>) -> Message {
        let addr_ascii = [0x61, 0x64, 0x64, 0x72, 0, 0, 0, 0, 0, 0, 0, 0];
        let addrs: Vec<u8> = Vec::new();
        let mut addr = Message {
            command: addr_ascii,
            payload: addrs,
        };
        addr.payload
            .extend_from_slice(&u16_to_array_of_u8(active_nodes.len() as u16));
        for (sock, ts) in active_nodes {
            let ip_octets = match sock.ip() {
                net::IpAddr::V4(ip) => ip.octets(),
                net::IpAddr::V6(_) => continue,
            };
            addr.payload.extend_from_slice(&ip_octets);
            addr.payload
                .extend_from_slice(&u16_to_array_of_u8(sock.port()));
            addr.payload.extend_from_slice(&u64_to_array_of_u8(*ts));
        }
        addr
    }
    fn deserialize(payload: &[u8]) -> Vec<Addr> {
        let len = byteorder::BigEndian::read_u16(&payload[0..2]);
        let mut offset = 0;
        let addr_length = 4 + 2 + 8;
        let header_length = 2;
        let mut addresses: Vec<Addr> = Vec::new();
        for _ in 0..len {
            let addr = &payload
                [header_length + offset..header_length + offset + addr_length];
            let ip_len = 4;
            let port_len = 2;
            let ts_len = 8;
            let ts = byteorder::BigEndian::read_u64(
                &addr[ip_len + port_len..ip_len + port_len + ts_len],
            );
            let port = byteorder::BigEndian::read_u16(
                &addr[ip_len..ip_len + port_len],
            );
            let ip = &addr[..addr_length];
            let ipv4 = net::Ipv4Addr::new(ip[0], ip[2], ip[2], ip[3]);
            let address = net::SocketAddr::new(net::IpAddr::V4(ipv4), port);
            addresses.push(Addr {
                address: address,
                ts: ts,
            });
            offset += addr_length;
        }
        addresses
    }
}

impl Message {
    // fn _new(buf: &[u8]) -> Message {
    //     //
    // }
    fn serialize(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        // magic numbers
        out.extend_from_slice(&[0xF9, 0xBE, 0xB4, 0xD9]);
        // command
        out.extend_from_slice(&self.command);
        // length
        out.extend_from_slice(&u32_to_array_of_u8(self.payload.len() as u32));
        // checksum
        out.extend_from_slice(&sha_256_bytes(&sha_256_bytes(&self.payload))
            [..4]
            .to_vec());
        out.extend(&self.payload);
        out
    }

    fn deserialize(buf: &[u8]) -> (&[u8], &[u8]) {
        // TODO confirm magic numbers

        let u32_len: usize = 4;
        let checksum_len: usize = 4;
        let len = byteorder::BigEndian::read_u32(
            &buf[MAGIC_NUMBER_SIZE + COMMAND_SIZE
                     ..MAGIC_NUMBER_SIZE + COMMAND_SIZE + u32_len],
        ) as usize;
        println!("{:?}", len);
        let header_offset =
            MAGIC_NUMBER_SIZE + COMMAND_SIZE + u32_len + checksum_len;
        let payload = &buf[header_offset..header_offset + len];
        let _checksum = &sha_256_bytes(&sha_256_bytes(payload))[..4];
        (
            &buf[MAGIC_NUMBER_SIZE..MAGIC_NUMBER_SIZE + COMMAND_SIZE],
            payload,
        )
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
    pk: [u8; 64],
    signature: [u8; 64],
}

struct TxOut {
    destination: [u8; 64],
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
    pk: [u8; 64],
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

fn fetch_wallet() -> Wallet {
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

fn create_new_address() {
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

fn list_addresses() {
    let wallet = fetch_wallet();
    for address in wallet.addresses {
        println!("{}", address.address());
    }
}

impl Address {
    fn new() -> Address {
        // https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
        let secp = secp256k1::Secp256k1::new();
        let mut rng = OsRng::new().unwrap();
        let (secret_key, public_key) = secp.generate_keypair(&mut rng).unwrap();
        let mut sk = [0u8; 32];
        sk[..].clone_from_slice(&secret_key[..32]);
        let mut pk = [0u8; 64];
        // first byte is 4
        pk[..].clone_from_slice(&public_key.serialize_uncompressed()[1..65]);
        Address { pk: pk, sk: sk }
    }

    fn address(&self) -> String {
        address_from_pk(self.pk)
    }

    fn serialize(&self) -> [u8; (32 + 64)] {
        let mut out = [0; (32 + 64)];
        let bytes = [&self.sk[..], &self.pk[..]].concat();
        out[..].clone_from_slice(&bytes);
        out
    }
}

impl Wallet {
    fn serialize(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.push(self.version[0]);
        out.push(self.version[1]);
        let length = self.addresses.len() as u8;
        println!("{:?}", length);
        out.push(length);
        println!("{:?}", out);
        for i in 0..length {
            let index = i as usize;
            let address = self.addresses[index].serialize();
            for i in 0..(32 + 64) {
                out.push(address[i]);
            }
        }
        println!("{:?}", out);
        out
    }
}

fn address_from_pk(pk: [u8; 64]) -> String {
    let mut result_bytes = sha_256_bytes(&pk[0..64]);

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
    address.to_base58()
}

impl Block {
    // let length = (3*4) + (32);
    fn bytes_to_hash(&self) -> [u8; (2 + 4 + 32 + 8 + 8 + 32)] {
        let index_u8a = u32_to_array_of_u8(self.index);
        let nonce_u8a = u64_to_array_of_u8(self.nonce);
        let timestamp_u8a = u64_to_array_of_u8(self.timestamp);
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

    fn hash(&self) -> [u8; 32] {
        sha_256_bytes(&self.bytes_to_hash())
    }
}

fn transactions_merkle_root(transactions: &Vec<Transaction>) -> [u8; 32] {
    let mut items: Vec<[u8; 32]> = Vec::new();
    for transaction in transactions {
        items.push(sha_256_bytes(&sha_256_bytes(&transaction.serialize())));
    }
    merkle(items)
}

// as a verb?
fn merkle(items: Vec<[u8; 32]>) -> [u8; 32] {
    let items = if items.len() == 1 {
        items
    } else {
        merkle_process_nodes(items)
    };
    sha_256_bytes(&sha_256_bytes(&items[0]))
}
fn merkle_process_nodes(mut items: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = Vec::new();
    if items.len() % 2 == 1 {
        // Copy the last item to make the leaf count even if necessary
        let mut last_item = [0; 32];
        last_item[..].copy_from_slice(&items[items.len() - 1][..]);
        items.push(last_item);
    }
    for _ in 0..(items.len() / 2) {
        let right = items.pop().unwrap();
        let left = items.pop().unwrap();
        let result =
            sha_256_bytes(&sha_256_bytes(&[&left[..], &right[..]].concat()));
        out.push(result)
    }
    if out.len() == 1 {
        return out;
    }
    return merkle_process_nodes(out);
}

impl TxIn {}

impl TxIn {
    fn serialize(&self) -> Vec<u8> {
        [
            &u32_to_array_of_u8(self.tx_index)[..],
            &self.previous_tx[..],
            &u64_to_array_of_u8(self.amount)[..],
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
        let message = secp256k1::Message::from_slice(&bytes).unwrap();
        let result = secp.sign(&message, &sk).expect("Failed to sign");
        let signature = result.serialize_compact(&secp);
        &self.signature[..].clone_from_slice(&signature);
    }
}

impl TxOut {
    fn serialize(&self) -> Vec<u8> {
        [&self.destination[..], &u64_to_array_of_u8(self.amount)[..]].concat()
    }
}

impl Transaction {
    fn serialize(&self) -> Vec<u8> {
        let in_len = u32_to_array_of_u8(self.tx_in.len() as u32);
        let out_len = u32_to_array_of_u8(self.tx_in.len() as u32);
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

    fn hash(&self) -> [u8; 32] {
        sha_256_bytes(&self.serialize())
    }
}

// TODO: implement these are traits on u16/u32?
fn u16_to_array_of_u8(x: u16) -> [u8; 2] {
    let b1: u8 = ((x >> 8) & 0xff) as u8;
    let b2: u8 = (x & 0xff) as u8;
    return [b1, b2];
}

fn array_of_u8_to_u32(x: [u8; 4]) -> u32 {
    byteorder::BigEndian::read_u32(&x)
}

fn u32_to_array_of_u8(x: u32) -> [u8; 4] {
    let mut out = [0; 4];
    byteorder::BigEndian::write_u32(&mut out, x);
    out
}

fn array_of_u8_to_u64(x: [u8; 8]) -> u64 {
    byteorder::BigEndian::read_u64(&x)
}

fn u64_to_array_of_u8(x: u64) -> [u8; 8] {
    let mut out = [0; 8];
    byteorder::BigEndian::write_u64(&mut out, x);
    out
}

fn create_coinbase_transaction(destination: [u8; 64]) -> Transaction {
    let tx_in = TxIn {
        previous_tx: coinbase(),
        tx_index: 0,
        amount: 5000000000,
        pk: [0; 64],
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

fn hash_is_valid_with_current_difficulty(hash: [u8; 32]) -> bool {
    let hash_u256 = U256::from_big_endian(&hash);
    // let difficulty = [
    //     0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // ];
    let difficulty = [
        0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let difficulty = U256::from_big_endian(&difficulty);
    return hash_u256 < difficulty;
}

fn mine_genesis_block() -> Block {
    let address = Address::new();
    println!("sk {:?}", &address.sk[..32]);
    let transaction = create_coinbase_transaction(address.pk);
    let transactions = vec![transaction];
    // one transaction, so just double sha it

    let mut block = Block {
        index: 0,
        version: [0; 2],
        merkle_root: transactions_merkle_root(&transactions),
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
    use super::create_coinbase_transaction;
    use super::transactions_merkle_root;
    use super::array_of_u8_to_u32;
    use super::array_of_u8_to_u64;
    use super::u32_to_array_of_u8;
    use super::u64_to_array_of_u8;
    use super::{Address, Block, Transaction, TxIn, TxOut};

    #[test]
    fn int_transform_verify() {
        assert_eq!(
            array_of_u8_to_u32(u32_to_array_of_u8(567901234u32)),
            567901234u32
        );
        assert_eq!(
            array_of_u8_to_u64(u64_to_array_of_u8(567901234u64)),
            567901234u64
        );
    }

    #[test]
    fn ascii_verify() {
        assert_eq!(
            String::from_utf8_lossy(&[
                0x70, 0x6f, 0x6e, 0x67, 0, 0, 0, 0, 0, 0, 0, 0
            ]),
            "pong\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}".to_string()
        );
    }

    #[test]
    fn verify_genesis_block() {
        let _sk: [u8; 32] = [
            37, 80, 185, 241, 1, 193, 142, 141, 126, 125, 221, 123, 78, 164,
            164, 42, 171, 220, 35, 33, 155, 143, 151, 73, 28, 28, 252, 88, 65,
            236, 190, 138,
        ];
        let hash: [u8; 32] = [
            0, 0, 16, 209, 176, 119, 41, 220, 136, 124, 227, 200, 64, 253, 93,
            164, 85, 175, 8, 94, 64, 63, 255, 201, 184, 200, 252, 123, 27, 81,
            238, 88,
        ];
        let nonce: u64 = 24930;
        let ts: u64 = 1518313606;
        let pk: [u8; 64] = [
            114, 32, 241, 194, 225, 116, 46, 154, 46, 124, 62, 72, 64, 1, 153,
            181, 137, 248, 106, 16, 108, 176, 187, 132, 110, 121, 201, 107, 90,
            163, 62, 146, 96, 4, 58, 122, 27, 136, 3, 153, 206, 86, 217, 154,
            220, 99, 114, 228, 88, 4, 90, 183, 40, 125, 218, 41, 151, 160, 203,
            104, 254, 111, 79, 6,
        ];
        let transaction = create_coinbase_transaction(pk);
        let transactions = vec![transaction];
        let block = Block {
            index: 0,
            version: [0; 2],
            merkle_root: transactions_merkle_root(&transactions),
            prev_hash: [0; 32],
            transactions: transactions,
            nonce: nonce,
            timestamp: ts,
        };
        assert_eq!(hash, block.hash());
        println!("{:?}", block.hash());

        // 25.0 bitcoin to new address
        let to_address = Address::new();
        let mut tx_in = TxIn {
            previous_tx: block.transactions[0].hash(),
            tx_index: 0,
            amount: 5000000000,
            pk: to_address.pk,
            signature: [0; 64],
        };
        tx_in.sign(&to_address.sk);

        // half to the destination
        let tx_out_1 = TxOut {
            destination: to_address.pk,
            amount: 2500000000,
        };
        // the "change"
        let tx_out_2 = TxOut {
            destination: pk,
            amount: 2500000000,
        };

        let _transaction = Transaction {
            tx_in: vec![tx_in],
            tx_out: vec![tx_out_1, tx_out_2],
        };
    }
}
