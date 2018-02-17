use bigint::uint::U256;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

// as a verb?
pub fn merkle(items: Vec<[u8; 32]>) -> [u8; 32] {
    let items = if items.len() == 1 {
        items
    } else {
        merkle_process_nodes(items)
    };
    sha_256_bytes(&sha_256_bytes(&items[0]))
}

pub fn merkle_process_nodes(mut items: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
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

pub fn coinbase() -> [u8; 32] {
    // "coinbase"
    // let coinbasehex = 0x636f696e62617365
    let mut out = [0; 32];
    out[..8].clone_from_slice(
        &[0x63, 0x6f, 0x69, 0x6e, 0x62, 0x61, 0x73, 0x65][..],
    );
    out
}


pub fn sha_256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.input(bytes);
    let mut out = [0; 32];
    sha.result(&mut out);
    out
}

pub fn current_epoch() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    return since_the_epoch.as_secs();
}

pub fn hash_is_valid_with_current_difficulty(hash: [u8; 32]) -> bool {
    let hash_u256 = U256::from_big_endian(&hash);
    // let difficulty = [
    //     0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // ];
    let difficulty = [
        0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let difficulty = U256::from_big_endian(&difficulty);
    return hash_u256 < difficulty;
}


