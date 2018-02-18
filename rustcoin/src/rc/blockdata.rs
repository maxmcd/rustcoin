use rc::constants::{HASH_SIZE, PK_SIZE, SIG_SIZE};
use rc::encode::Encodable;
use rc::util::{merkle, sha_256_bytes};
use rc::util;

use bigint::uint::U256;
use crypto::digest::Digest;
use crypto::ripemd160::Ripemd160;
use rand::OsRng;
use rust_base58::ToBase58;
use self::secp256k1::key::SecretKey;

extern crate secp256k1;

pub struct Wallet {
    pub version: [u8; 2],
    pub addresses: Vec<Address>,
}

impl Wallet {
    pub fn serialize(&self) -> Vec<u8> {
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

pub struct Transaction {
    tx_in: Vec<TxIn>,
    tx_out: Vec<TxOut>,
}

impl Transaction {
    pub fn create_coinbase_transaction(destination: [u8; 64]) -> Transaction {
        let tx_in = TxIn {
            previous_tx: util::coinbase(),
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
    pub fn serialize(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        (self.tx_in.len() as u32).serialize(&mut out);
        for tx_in in &self.tx_in {
            out.extend_from_slice(&tx_in.serialize())
        }
        (self.tx_out.len() as u32).serialize(&mut out);
        for tx_out in &self.tx_out {
            out.extend_from_slice(&tx_out.serialize())
        }
        out
    }

    fn _hash(&self) -> [u8; 32] {
        util::sha_256_bytes(&self.serialize())
    }

    pub fn deserialize(buf: &mut Vec<u8>) -> Transaction {
        let mut tx_in: Vec<TxIn> = Vec::new();
        let mut tx_out: Vec<TxOut> = Vec::new();
        let tx_in_len: u32 = Encodable::deserialize(buf);
        for _ in 0..tx_in_len {
            tx_in.push(TxIn::deserialize(buf));
        }
        let tx_out_len: u32 = Encodable::deserialize(buf);
        for _ in 0..tx_out_len {
            tx_out.push(TxOut::deserialize(buf));
        }
        Transaction {
            tx_in: tx_in,
            tx_out: tx_out,
        }
    }
}

pub trait MerkleRoot {
    fn merkle_root(&self) -> [u8; 32];
}
impl MerkleRoot for Vec<Transaction> {
    fn merkle_root(&self) -> [u8; 32] {
        let mut items: Vec<[u8; 32]> = Vec::new();
        for transaction in self {
            items.push(sha_256_bytes(&sha_256_bytes(&transaction.serialize())));
        }
        merkle(items)
    }
}

struct TxIn {
    tx_index: u32,
    previous_tx: [u8; 32], // hash is coinbase() for coinbase transaction
    amount: u64,
    pk: [u8; 64],
    signature: [u8; 64],
}

impl TxIn {
    fn serialize(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        self.tx_index.serialize(&mut out);
        self.previous_tx.serialize(&mut out);
        self.amount.serialize(&mut out);
        self.pk.serialize(&mut out);
        self.signature.serialize(&mut out);
        out
    }

    fn _sign(&mut self, sk: &[u8; 32]) {
        let secp = secp256k1::Secp256k1::new();
        let sk = SecretKey::from_slice(&secp, sk).unwrap();
        let bytes = self.serialize();
        let bytes = &bytes[..(bytes.len() - 64)]; // remove empty sig
        let bytes = util::sha_256_bytes(&bytes);
        let message = secp256k1::Message::from_slice(&bytes).unwrap();
        let result = secp.sign(&message, &sk).expect("Failed to sign");
        let signature = result.serialize_compact(&secp);
        &self.signature[..].clone_from_slice(&signature);
    }

    fn deserialize(buf: &mut Vec<u8>) -> TxIn {
        let tx_index: u32 = Encodable::deserialize(buf);
        let previous_tx: [u8; HASH_SIZE] = Encodable::deserialize(buf);
        let amount: u64 = Encodable::deserialize(buf);
        let pk: [u8; PK_SIZE] = Encodable::deserialize(buf);
        let signature: [u8; SIG_SIZE] = Encodable::deserialize(buf);
        return TxIn {
            tx_index: tx_index,
            previous_tx: previous_tx,
            amount: amount,
            pk: pk,
            signature: signature,
        };
    }
}

struct TxOut {
    destination: [u8; 64],
    amount: u64,
}

impl TxOut {
    fn serialize(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        self.destination.serialize(&mut out);
        self.amount.serialize(&mut out);
        out
    }

    fn deserialize(buf: &mut Vec<u8>) -> TxOut {
        let destination: [u8; PK_SIZE] = Encodable::deserialize(buf);
        let amount: u64 = Encodable::deserialize(buf);
        return TxOut {
            destination: destination,
            amount: amount,
        };
    }
}

pub struct Block {
    pub version: [u8; 2],
    pub index: u32,
    pub prev_hash: [u8; 32],
    pub transactions: Vec<Transaction>,
    pub nonce: u64,
    pub timestamp: u64,
    pub merkle_root: [u8; 32],
}

impl Block {
    fn bytes_to_hash(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        self.version.serialize(&mut out);
        self.index.serialize(&mut out);
        self.prev_hash.serialize(&mut out);
        self.nonce.serialize(&mut out);
        self.timestamp.serialize(&mut out);
        self.merkle_root.serialize(&mut out);
        out
    }

    pub fn genesis_block() -> Block {
        let nonce: u64 = 61090;
        let ts: u64 = 1518534873;
        let pk: [u8; 64] = [
            131, 153, 89, 70, 234, 230, 140, 10, 87, 8, 195, 104, 112, 207,
            162, 152, 3, 177, 70, 181, 118, 138, 178, 233, 67, 190, 138, 89,
            35, 118, 74, 15, 101, 171, 220, 156, 132, 35, 153, 242, 221, 134,
            21, 113, 224, 241, 218, 198, 195, 117, 117, 243, 235, 73, 155, 25,
            210, 16, 127, 62, 123, 59, 191, 13,
        ];
        let transaction = Transaction::create_coinbase_transaction(pk);
        let transactions = vec![transaction];
        let block = Block {
            index: 0,
            version: [0; 2],
            merkle_root: transactions.merkle_root(),
            prev_hash: [0; 32],
            transactions: transactions,
            nonce: nonce,
            timestamp: ts,
        };
        block
    }

    pub fn hash(&self) -> [u8; 32] {
        sha_256_bytes(&self.bytes_to_hash())
    }

    pub fn deserialize(buf: &mut Vec<u8>) -> Block {
        let version: [u8; 2] = Encodable::deserialize(buf);
        let index: u32 = Encodable::deserialize(buf);
        let prev_hash: [u8; HASH_SIZE] = Encodable::deserialize(buf);
        let nonce: u64 = Encodable::deserialize(buf);
        let timestamp: u64 = Encodable::deserialize(buf);
        let merkle_root: [u8; HASH_SIZE] = Encodable::deserialize(buf);
        let tx_len: u32 = Encodable::deserialize(buf);
        let mut transactions: Vec<Transaction> = Vec::new();

        for _ in 0..tx_len {
            transactions.push(Transaction::deserialize(buf));
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

    pub fn serialize(&self) -> Vec<u8> {
        let mut block_bytes = self.bytes_to_hash();
        (self.transactions.len() as u32).serialize(&mut block_bytes);
        for transaction in &self.transactions {
            block_bytes.extend_from_slice(&transaction.serialize())
        }
        block_bytes
    }
}

pub struct Address {
    pub sk: [u8; 32],
    pub pk: [u8; 64],
}

impl Address {
    pub fn new() -> Address {
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

    pub fn address(&self) -> String {
        address_from_pk(self.pk)
    }

    fn serialize(&self) -> [u8; (32 + 64)] {
        let mut out = [0; (32 + 64)];
        let bytes = [&self.sk[..], &self.pk[..]].concat();
        out[..].clone_from_slice(&bytes);
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
    let sha_twice = util::sha_256_bytes(&util::sha_256_bytes(&with_version));
    let mut address = [0; 25];
    address[..21].clone_from_slice(&with_version[..21]);
    address[21..25].clone_from_slice(&sha_twice[..4]);
    address.to_base58()
}

pub fn mine_genesis_block() -> Block {
    let address = Address::new();
    println!("sk {:?}", &address.sk[..32]);
    let transaction = Transaction::create_coinbase_transaction(address.pk);
    let transactions = vec![transaction];
    // one transaction, so just double sha it

    let mut block = Block {
        index: 0,
        version: [0; 2],
        merkle_root: transactions.merkle_root(),
        prev_hash: [0; 32],
        transactions: transactions,
        nonce: 0,
        timestamp: util::current_epoch(),
    };

    loop {
        let hash = block.hash();
        if util::hash_is_valid_with_current_difficulty(hash) {
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

#[cfg(test)]
mod tests {
    use super::{Address, Block, Transaction, TxIn, TxOut};

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
        let block = Block::genesis_block();
        assert_eq!(hash, block.hash());

        let mut serialized_tx_in = block.transactions[0].tx_in[0].serialize();
        assert_eq!(
            block.transactions[0].tx_in[0].serialize(),
            TxIn::deserialize(&mut serialized_tx_in).serialize()
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
            previous_tx: block.transactions[0]._hash(),
            tx_index: 0,
            amount: 5000000000,
            pk: to_address.pk,
            signature: [0; 64],
        };
        tx_in._sign(&to_address.sk);

        // half to the destination
        let tx_out_1 = TxOut {
            destination: to_address.pk,
            amount: 2500000000,
        };
        // the "change"
        let tx_out_2 = TxOut {
            destination: block.transactions[0].tx_out[0].destination,
            amount: 2500000000,
        };

        let _transaction = Transaction {
            tx_in: vec![tx_in],
            tx_out: vec![tx_out_1, tx_out_2],
        };
    }
}
