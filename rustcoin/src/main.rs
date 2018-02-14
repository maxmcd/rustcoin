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
const VERSION_SIZE: usize = 2;
const INDEX_SIZE: usize = 4;
const U32_SIZE: usize = 4;
const U64_SIZE: usize = 8;
const NONCE_SIZE: usize = 8;
const TS_SIZE: usize = 8;
const HASH_SIZE: usize = 32;
const TX_IN_SIZE: usize = (4 + 32 + 8 + 64 + 64);
const TX_OUT_SIZE: usize = (64 + 8);
const PK_SIZE: usize = 64;
const SIG_SIZE: usize = 64;

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
            "mine-genesis-block" => {
                mine_genesis_block();
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
    }
}

fn start_node() {
    let port = match env::var("PORT") {
        Ok(port) => port,
        Err(_) => "8333".to_string(),
    };


    // let known_node = "rustcoin:8333";
    let known_node = "127.0.0.1:8333";

    println!("{}: {}", port, "Fetching blocks");
    let mut blocks = fetch_blocks();
    if blocks.len() == 0 {
        println!("{}: {}", port, "No blocks found, writing genesis block.");
        blocks.push(genesis_block());
        write_blocks(&blocks);
    }

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

    let socket = net::UdpSocket::bind(format!("0.0.0.0:{}", &port)).unwrap();

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
            println!("{}: Sent getaddr to {}", port, &node);
        }
    }

    let send_socket = socket.try_clone().unwrap();
    // // Message sender
    // thread::spawn(move || {

    // });

    // Scheduled task sender
    let thread_port = String::from(port.as_ref());
    thread::spawn(move || {
        let active_nodes_rw = Arc::clone(&active_nodes_arc);
        let ping = Message {
            payload: Vec::new(),
            command: [0x70, 0x69, 0x6e, 0x67, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        loop {
            thread::sleep(time::Duration::from_millis(10000));
            let active_nodes = active_nodes_rw.read().unwrap();
            for (node, _) in active_nodes.iter() {
                println!("{}: Sent ping to {}", thread_port, &node);
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
        println!("{}: Command \"{}\" from {}", port, command, src);
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
                            println!("{}: Adding node address {}", port, address.address);
                            active_nodes.insert(address.address
                                , address.ts);
                        }
                    }

                }
            }
            "pong\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}" => {}
            &_ => {
                println!("{}: No match for command {}", port, command);
            }
        }
    }
}

struct Message {
    command: [u8; 12],
    payload: Vec<u8>,
}

struct GetBlocks {
    hash: [u8; 32],
}

struct Addr {
    address: net::SocketAddr,
    ts: u64,
}
struct Ping {
    address: net::SocketAddr,
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

fn fetch_blocks() -> Vec<Block> {
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

fn write_blocks(blocks: &Vec<Block>) {
    let mut blockdata = fs::OpenOptions::new()
        .write(true)
        .open(&rustcoin_dir().join("blockdata.dat"))
        .unwrap();
    let mut to_write: Vec<u8> = Vec::new();
    to_write.extend_from_slice(&u32_to_array_of_u8(blocks.len() as u32));
    for block in blocks {
        to_write.extend(block.serialize());
    }
    blockdata.write_all(&to_write).unwrap();
    blockdata.sync_data().unwrap();
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
        out.push(length);
        for i in 0..length {
            let index = i as usize;
            let address = self.addresses[index].serialize();
            for i in 0..(32 + 64) {
                out.push(address[i]);
            }
        }
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
    fn bytes_to_hash(&self) -> Vec<u8> {
        let index_u8a = u32_to_array_of_u8(self.index);
        let nonce_u8a = u64_to_array_of_u8(self.nonce);
        let timestamp_u8a = u64_to_array_of_u8(self.timestamp);
        [
            &self.version[..],
            &index_u8a[..],
            &self.prev_hash[..],
            &nonce_u8a,
            &timestamp_u8a,
            &self.merkle_root,
        ].concat()
    }

    fn hash(&self) -> [u8; 32] {
        sha_256_bytes(&self.bytes_to_hash())
    }

    fn deserialize(buf: &mut [u8]) -> Block {
        let mut offset = 0;
        let mut version = [0; VERSION_SIZE];
        version[..].copy_from_slice(&buf[offset..VERSION_SIZE]);
        offset += VERSION_SIZE;
        let index = array_of_u8_to_u32(&buf[offset..offset + INDEX_SIZE]);
        offset += INDEX_SIZE;
        let mut prev_hash = [0; HASH_SIZE];
        prev_hash[..].copy_from_slice(&buf[offset..offset + HASH_SIZE]);
        offset += HASH_SIZE;
        let nonce = array_of_u8_to_u64(&buf[offset..offset + NONCE_SIZE]);
        offset += NONCE_SIZE;
        let timestamp = array_of_u8_to_u64(&buf[offset..offset + TS_SIZE]);
        offset += TS_SIZE;
        let mut merkle_root = [0; HASH_SIZE];
        merkle_root[..].copy_from_slice(&buf[offset..offset + HASH_SIZE]);
        offset += HASH_SIZE;
        let tx_len = array_of_u8_to_u32(&buf[offset..offset + U32_SIZE]);
        offset += U32_SIZE;
        let mut transactions: Vec<Transaction> = Vec::new();

        let mut buf = &mut buf[offset..];

        for _ in 0..tx_len {
            transactions.push(Transaction::deserialize(&mut buf));
        }

        Block {
            version: version,
            index: index,
            prev_hash: prev_hash,
            nonce: nonce,
            timestamp: timestamp,
            merkle_root: merkle_root,
            transactions: transactions,
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut block_bytes = self.bytes_to_hash();
        block_bytes.extend_from_slice(&u32_to_array_of_u8(self.transactions
            .len()
            as u32));
        for transaction in &self.transactions {
            block_bytes.extend_from_slice(&transaction.serialize())
        }
        block_bytes
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

    fn deserialize(buf: &[u8]) -> TxIn {
        let mut offset = 0;
        let tx_index = array_of_u8_to_u32(&buf[offset..offset + U32_SIZE]);
        offset += U32_SIZE;
        let mut previous_tx = [0; HASH_SIZE];
        previous_tx[..].copy_from_slice(&buf[offset..offset + HASH_SIZE]);
        offset += HASH_SIZE;
        let amount = array_of_u8_to_u64(&buf[offset..offset + U64_SIZE]);
        offset += U64_SIZE;
        let mut pk = [0; PK_SIZE];
        pk[..].copy_from_slice(&buf[offset..offset + PK_SIZE]);
        offset += PK_SIZE;
        let mut signature = [0; SIG_SIZE];
        signature[..].copy_from_slice(&buf[offset..offset + SIG_SIZE]);
        return TxIn {
            tx_index: tx_index,
            previous_tx: previous_tx,
            amount: amount,
            pk: pk,
            signature: signature,
        };
    }
}

impl TxOut {
    fn serialize(&self) -> Vec<u8> {
        [&self.destination[..], &u64_to_array_of_u8(self.amount)[..]].concat()
    }

    fn deserialize(buf: &[u8]) -> TxOut {
        let mut offset = 0;
        let mut destination = [0; PK_SIZE];
        destination[..].copy_from_slice(&buf[offset..offset + PK_SIZE]);
        offset += PK_SIZE;
        let amount = array_of_u8_to_u64(&buf[offset..offset + U64_SIZE]);
        return TxOut {
            destination: destination,
            amount: amount,
        };
    }
}

impl Transaction {
    fn serialize(&self) -> Vec<u8> {
        let in_len = u32_to_array_of_u8(self.tx_in.len() as u32);
        let out_len = u32_to_array_of_u8(self.tx_in.len() as u32);
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&in_len);
        for tx_in in &self.tx_in {
            out.extend_from_slice(&tx_in.serialize())
        }
        out.extend_from_slice(&out_len);
        for tx_out in &self.tx_out {
            out.extend_from_slice(&tx_out.serialize())
        }
        out
    }

    fn hash(&self) -> [u8; 32] {
        sha_256_bytes(&self.serialize())
    }

    fn deserialize(buf: &mut [u8]) -> Transaction {
        let mut offset = 0;
        let mut tx_in: Vec<TxIn> = Vec::new();
        let mut tx_out: Vec<TxOut> = Vec::new();
        let tx_in_len = array_of_u8_to_u32(&buf[offset..offset + U32_SIZE]);
        offset += U32_SIZE;
        for _ in 0..tx_in_len {
            tx_in.push(TxIn::deserialize(&buf[offset..]));
            offset += TX_IN_SIZE;
        }
        let tx_out_len = array_of_u8_to_u32(&buf[offset..offset + U32_SIZE]);
        offset += U32_SIZE;
        for _ in 0..tx_out_len {
            tx_out.push(TxOut::deserialize(&buf[offset..]));
            offset += TX_OUT_SIZE;
        }
        let buf = &mut buf[offset..];
        Transaction {
            tx_in: tx_in,
            tx_out: tx_out,
        }
    }
}

fn u16_to_array_of_u8(x: u16) -> [u8; 2] {
    let b1: u8 = ((x >> 8) & 0xff) as u8;
    let b2: u8 = (x & 0xff) as u8;
    return [b1, b2];
}

fn array_of_u8_to_u32(x: &[u8]) -> u32 {
    byteorder::BigEndian::read_u32(x)
}

fn u32_to_array_of_u8(x: u32) -> [u8; 4] {
    let mut out = [0; 4];
    byteorder::BigEndian::write_u32(&mut out, x);
    out
}

fn array_of_u8_to_u64(x: &[u8]) -> u64 {
    byteorder::BigEndian::read_u64(x)
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

fn genesis_block() -> Block {
    let nonce: u64 = 61090;
    let ts: u64 = 1518534873;
    let pk: [u8; 64] = [
        131, 153, 89, 70, 234, 230, 140, 10, 87, 8, 195, 104, 112, 207,
        162, 152, 3, 177, 70, 181, 118, 138, 178, 233, 67, 190, 138, 89,
        35, 118, 74, 15, 101, 171, 220, 156, 132, 35, 153, 242, 221, 134,
        21, 113, 224, 241, 218, 198, 195, 117, 117, 243, 235, 73, 155, 25,
        210, 16, 127, 62, 123, 59, 191, 13,
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
    block
}

#[cfg(test)]
mod tests {
    use super::create_coinbase_transaction;
    use super::transactions_merkle_root;
    use super::genesis_block;
    use super::{Address, Block, Transaction, TxIn, TxOut};

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
            78, 21, 143, 5, 35, 237, 232, 172, 88, 192, 203, 62, 139, 246, 119,
            45, 190, 229, 92, 94, 143, 194, 190, 51, 152, 129, 179, 25, 213,
            141, 199, 126,
        ];
        let hash: [u8; 32] = [
            0, 0, 245, 152, 196, 151, 40, 119, 162, 151, 65, 221, 187, 19, 138,
            67, 94, 158, 19, 94, 23, 205, 152, 189, 229, 50, 91, 189, 112, 1,
            77, 223,
        ];
        let block = genesis_block();
        assert_eq!(hash, block.hash());

        assert_eq!(
            block.transactions[0].tx_in[0].serialize(),
            TxIn::deserialize(&block.transactions[0].tx_in[0].serialize())
                .serialize()
        );

        let mut serialized_transaction = block.transactions[0].serialize();
        assert_eq!(
            block.transactions[0].serialize(),
            Transaction::deserialize(&mut serialized_transaction).serialize()
        );

        let mut serialized_block = block.serialize();
        assert_eq!(
            block.serialize(),
            Block::deserialize(&mut serialized_block).serialize()
        );

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
