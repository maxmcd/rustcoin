pub const U32_SIZE: usize = 4;
pub const HASH_SIZE: usize = 32;
pub const PK_SIZE: usize = 64;
pub const SIG_SIZE: usize = 64;

pub const GETBLOCKS_CMD: [u8; 12] = [0x67, 0x65, 0x74, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x73, 0, 0, 0];
pub const GETADDR_CMD: [u8; 12] = [0x67, 0x65, 0x74, 0x61, 0x64, 0x64, 0x72, 0, 0, 0, 0, 0];