pub trait Hexable {
    fn to_hex(&self) -> String;
}

impl<T: AsRef<[u8]>> Hexable for T {
    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self))
    }
}
