use chrono::NaiveDateTime;

// hacky workaround to estimate current state
#[derive(Default, Clone, Copy)]
pub struct ChainState {
    start: NaiveDateTime,
    block_number_at_start: u64,
    block_time: i64,
}

impl ChainState {
    pub fn new(start: NaiveDateTime, block_number_at_start: u64, block_time: i64) -> Self {
        Self { start, block_number_at_start, block_time }
    }
    pub async fn current_block(&self) -> u64 {
        let now = chrono::Local::now().naive_utc();
        let diff = now.signed_duration_since(self.start);
        let blocks_passed = (diff.num_seconds() / self.block_time) as u64;
        self.block_number_at_start + blocks_passed
    }
}
