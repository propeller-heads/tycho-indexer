use lazy_static::lazy_static;
use revm::primitives::U256;

lazy_static! {
    pub static ref EXTERNAL_ACCOUNT: String =
        String::from("0xf847a638E44186F3287ee9F8cAF73FF4d4B80784");
    pub static ref MAX_BALANCE: U256 = U256::MAX / U256::from(2);
    pub static ref ADAPTER_ADDRESS: String =
        String::from("0xA2C5C98A892fD6656a7F39A2f63228C0Bc846270");
}
