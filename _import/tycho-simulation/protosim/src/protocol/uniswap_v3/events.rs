use ethers::types::U256;

/// Underlying data structure for mint and burns
///
/// Mint- and BurnEvent below are wrapped so that
/// the From trait can be implemented for these on the UniswapV3
/// event enum
///
/// This means instead of having to type: `UniswapV3::Burn(LiquidityChangeData::new(...))`
/// every time we can simply use: `BurnEvent::new(...).into()`
#[derive(Debug)]
pub struct LiquidityChangeData {
    pub tick_upper: i32,
    pub tick_lower: i32,
    pub amount: u128,
}

#[derive(Debug)]
pub struct MintEvent(LiquidityChangeData);

impl MintEvent {
    pub fn new(lower: i32, upper: i32, amount: u128) -> Self {
        MintEvent(LiquidityChangeData {
            tick_lower: lower,
            tick_upper: upper,
            amount,
        })
    }
}

#[derive(Debug)]
pub struct BurnEvent(LiquidityChangeData);

impl BurnEvent {
    pub fn new(lower: i32, upper: i32, amount: u128) -> Self {
        BurnEvent(LiquidityChangeData {
            tick_lower: lower,
            tick_upper: upper,
            amount,
        })
    }
}

#[derive(Debug)]
pub struct SwapEvent {
    pub sqrt_price: U256,
    pub liquidity: u128,
    pub tick: i32,
}

impl SwapEvent {
    pub fn new(sqrt_price: U256, liquidity: u128, tick: i32) -> Self {
        SwapEvent {
            sqrt_price,
            liquidity,
            tick,
        }
    }
}

#[derive(Debug)]
pub enum UniswapV3Event {
    Mint(LiquidityChangeData),
    Burn(LiquidityChangeData),
    Swap(SwapEvent),
}

impl From<MintEvent> for UniswapV3Event {
    fn from(value: MintEvent) -> Self {
        UniswapV3Event::Mint(value.0)
    }
}

impl From<BurnEvent> for UniswapV3Event {
    fn from(value: BurnEvent) -> Self {
        UniswapV3Event::Burn(value.0)
    }
}

impl From<SwapEvent> for UniswapV3Event {
    fn from(value: SwapEvent) -> Self {
        UniswapV3Event::Swap(value)
    }
}
