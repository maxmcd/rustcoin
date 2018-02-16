extern crate byteorder;
use byteorder::{BigEndian, ByteOrder};

fn extend_vec(vec: &mut Vec<u8>, len: usize) {
    let vlen = vec.len();
    vec.resize(vlen + len, 0);
}

fn clip_vec(vec: &mut Vec<u8>, len: usize) {
    for _ in 0..len {
        vec.remove(0);
    }
}

pub trait Encodable {
    fn serialize(&self, o: &mut Vec<u8>);
    fn deserialize(o: &mut Vec<u8>) -> Self;
}

macro_rules! impl_ints {
    ( $ty:ident, $meth_write:ident, $meth_read:ident, $bytes:expr ) => (
        impl Encodable for $ty {
            fn serialize(&self, mut o: &mut Vec<u8>) {
                extend_vec(&mut o, $bytes);
                let vlen = o.len();
                BigEndian::$meth_write(&mut o[(vlen-$bytes)..], *self);
            }
            fn deserialize(mut o: &mut Vec<u8>) -> $ty {
                let out = BigEndian::$meth_read(&o[..$bytes]);
                clip_vec(&mut o, $bytes);
                out
            }
        }
    )
}

impl_ints!(u64, write_u64, read_u64, 8);
impl_ints!(u32, write_u32, read_u32, 4);
impl_ints!(u16, write_u16, read_u16, 2);

macro_rules! impl_array{
    ( $size:expr ) => (
        impl Encodable for [u8; $size] {
            fn serialize(&self, o: &mut Vec<u8>) {
                o.extend_from_slice(&self[..]);
            }
            fn deserialize(o: &mut Vec<u8>) -> [u8; $size] {
                let mut out = [0u8; $size];
                for x in 0..$size {
                    out[x] = o.remove(0);
                }
                out
            }
        }
    )
}
impl_array!(2);
impl_array!(4);
impl_array!(12);
impl_array!(32);
impl_array!(64);

#[cfg(test)]
mod tests {
    use super::Encodable;

    #[test]
    fn u16_and_u32() {
        let mut out: Vec<u8> = Vec::new();
        12u16.serialize(&mut out);
        14u32.serialize(&mut out);
        16u64.serialize(&mut out);
        let twelve: u16 = Encodable::deserialize(&mut out);
        let fourteen: u32 = Encodable::deserialize(&mut out);
        let sixteen: u64 = Encodable::deserialize(&mut out);
        assert_eq!(16u64, sixteen);
        assert_eq!(14u32, fourteen);
        assert_eq!(12u16, twelve);
    }
}
