use ethabi::ethereum_types::Address;
use substreams::Hex;

pub trait Hexable {
    fn to_hex(&self) -> String;
}

impl Hexable for Vec<u8> {
    fn to_hex(self: &Self) -> String {
        let mut str = Hex::encode(self);
        str.insert_str(0, "0x");
        str
    }
}

impl Hexable for Address {
    fn to_hex(self: &Self) -> String {
        self.as_bytes().to_vec().to_hex()
    }
}
