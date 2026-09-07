//! Turns Titan frames into [`Update`]s.

use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use chrono::Utc;
use num_bigint::BigUint;
use tycho_common::{
    models::{token::Token, Chain},
    simulation::protocol_sim::ProtocolSim,
    Bytes,
};

use super::{
    config::PriceLevelStreamConfig,
    state::{PriceLevelStreamQuote, PriceLevelStreamState},
    stream::PAMM_ADDRESS_ATTRIBUTE,
    telemetry,
    titan::{TitanPairLevels, TitanPammLevels, TitanPriceLevel, TitanPriceLevelMessage},
};
use crate::protocol::models::{ProtocolComponent, Update};

/// How long the data of one frame may be served without a fresher frame carrying it: two block
/// times. Titan streams at 1 Hz and its frames arrive within about 3 s of being built, so this
/// leaves ample margin for jitter while bounding stale exposure.
pub(super) const DEFAULT_STALE_AFTER: Duration = Duration::from_secs(24);

pub(super) const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Furthest a frame's `timestamp` may lie ahead of the local wall clock: one slot. Titan's
/// frames were observed at least 120 ms behind the local clock; anything ahead of it by more
/// than clock skew is implausible.
const MAX_FUTURE_SKEW_NANOS: u64 = 12 * NANOS_PER_SECOND;

/// Post-merge Ethereum slot duration in seconds.
const SECONDS_PER_SLOT: u64 = 12;

/// Extra blocks allowed beyond what elapsed time explains. Titan builds at chain head + 1 and
/// sometimes + 2, so a frame right after a block boundary may jump by two.
const BLOCK_JUMP_SLACK: u64 = 2;

/// The instants a tracker event is judged against.
#[derive(Clone, Copy, Debug)]
pub(super) struct Now {
    /// Wall clock, nanoseconds since the Unix epoch. Only ever compared against Titan's
    /// `timestamp`.
    pub wall_nanos: u64,
    /// Monotonic clock; drives every deadline, so a wall-clock jump cannot expire or freeze
    /// anything.
    pub instant: Instant,
}

impl Now {
    pub(super) fn current() -> Self {
        let wall_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|since_epoch| u64::try_from(since_epoch.as_nanos()).ok())
            .unwrap_or(0);
        Self { wall_nanos, instant: Instant::now() }
    }
}

/// Why a parsed frame was dropped before touching the served set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rejection {
    /// Built `stale_after` ago or earlier.
    TooOld,
    /// Built more than one slot ahead of the local clock.
    InFuture,
    /// Older than the newest accepted frame.
    OutOfOrder,
    /// Targets a block below the newest accepted one.
    BlockRegression,
    /// Targets a block further ahead than elapsed time allows.
    BlockJump,
}

impl Rejection {
    fn as_str(self) -> &'static str {
        match self {
            Rejection::TooOld => "too_old",
            Rejection::InFuture => "in_future",
            Rejection::OutOfOrder => "out_of_order",
            Rejection::BlockRegression => "block_regression",
            Rejection::BlockJump => "block_jump",
        }
    }
}

/// Turns Titan frames into [`Update`]s, tracking the previously emitted components so pair
/// additions and removals can be diffed against the last snapshot.
pub(super) struct SnapshotTracker {
    registry: HashMap<Bytes, PriceLevelStreamConfig>,
    /// Venues excluded from auto-detection. The builder keeps this disjoint from the registry:
    /// denying removes any registration and registering removes any denial.
    denied: HashSet<Bytes>,
    tokens: HashMap<Bytes, Token>,
    /// Whether frames from pAMMs absent from the registry get an address-named configuration
    /// synthesized (and cached in the registry) instead of being skipped.
    auto_detect: bool,
    /// The per-swap gas cost synthesized auto-detected configurations are served with.
    auto_detected_gas_cost: BigUint,
    /// Venues whose components are emitted under the `propammfallback:` family, so their swaps
    /// execute through Titan's PropAMMRouter instead of the venue directly.
    router_venues: HashSet<Bytes>,
    /// Components of the last emitted snapshot, across all pAMMs. A frame is a complete
    /// snapshot of everything Titan currently streams, so removals are diffed globally: a
    /// known component a frame does not re-emit is gone — including when its venue vanishes
    /// from the stream entirely.
    components: HashMap<String, ProtocolComponent>,
    /// The data freshness window; see [`DEFAULT_STALE_AFTER`].
    stale_after: Duration,
    /// The `timestamp` of the newest accepted frame. Frames older than it are out of order;
    /// equal ones are re-emissions within a build round and accepted. Never reset.
    newest_timestamp: u64,
    /// The block of the newest accepted frame. Later frames may not regress below it, nor jump
    /// further ahead than the elapsed time explains. Reset with `last_accepted`.
    newest_block: u64,
    /// When the newest frame was accepted; `None` before the first one and after the source
    /// returns to unserved, which skips the block checks for the next frame.
    last_accepted: Option<Instant>,
    /// Whether the last frame was rejected: the first rejection of a streak logs at WARN, the
    /// rest at DEBUG, and the counter carries the rate.
    rejecting: bool,
}

impl SnapshotTracker {
    pub(super) fn new(
        registry: HashMap<Bytes, PriceLevelStreamConfig>,
        denied: HashSet<Bytes>,
        tokens: HashMap<Bytes, Token>,
        auto_detect: bool,
        auto_detected_gas_cost: BigUint,
        router_venues: HashSet<Bytes>,
        stale_after: Duration,
    ) -> Self {
        Self {
            registry,
            denied,
            tokens,
            auto_detect,
            auto_detected_gas_cost,
            router_venues,
            components: HashMap::new(),
            stale_after,
            newest_timestamp: 0,
            newest_block: 0,
            last_accepted: None,
            rejecting: false,
        }
    }

    /// Checks a frame against the freshness and ordering rules, returning its age when it is
    /// acceptable.
    fn accept(&self, frame: &TitanPriceLevelMessage, now: Now) -> Result<Duration, Rejection> {
        let frame_age = Duration::from_nanos(
            now.wall_nanos
                .saturating_sub(frame.timestamp),
        );
        if frame_age >= self.stale_after {
            return Err(Rejection::TooOld);
        }
        if frame.timestamp >
            now.wall_nanos
                .saturating_add(MAX_FUTURE_SKEW_NANOS)
        {
            return Err(Rejection::InFuture);
        }
        if frame.timestamp < self.newest_timestamp {
            return Err(Rejection::OutOfOrder);
        }
        let Some(last_accepted) = self.last_accepted else {
            return Ok(frame_age);
        };
        if frame.block_number < self.newest_block {
            return Err(Rejection::BlockRegression);
        }
        let elapsed_slots = now
            .instant
            .saturating_duration_since(last_accepted)
            .as_secs() /
            SECONDS_PER_SLOT;
        let allowed = self
            .newest_block
            .saturating_add(elapsed_slots)
            .saturating_add(BLOCK_JUMP_SLACK);
        if frame.block_number > allowed {
            return Err(Rejection::BlockJump);
        }
        Ok(frame_age)
    }

    /// Processes one frame into an [`Update`], or `None` if the frame is rejected (see
    /// [`Rejection`]) or carries nothing relevant.
    pub(super) fn on_frame(&mut self, frame: TitanPriceLevelMessage, now: Now) -> Option<Update> {
        let frame_age = match self.accept(&frame, now) {
            Ok(frame_age) => frame_age,
            Err(rejection) => {
                self.log_rejection(rejection, &frame);
                telemetry::frame_rejected(rejection.as_str());
                return None;
            }
        };
        self.rejecting = false;
        telemetry::frame_accepted();
        self.newest_timestamp = frame.timestamp;
        self.newest_block = frame.block_number;
        self.last_accepted = Some(now.instant);
        let _ = frame_age;

        let mut states: HashMap<String, Box<dyn ProtocolSim>> = HashMap::new();
        let mut new_pairs = HashMap::new();
        // The frame is a complete snapshot: every known component is presumed gone until the
        // frame re-emits it below.
        let mut previous = std::mem::take(&mut self.components);

        for TitanPammLevels { pamm, pairs } in frame.pamms {
            let config = match self.registry.entry(pamm.clone()) {
                Entry::Occupied(entry) => &*entry.into_mut(),
                Entry::Vacant(entry) => {
                    if !self.auto_detect {
                        tracing::debug!(%pamm, "Skipping unregistered pAMM");
                        continue;
                    }
                    if self.denied.contains(&pamm) {
                        tracing::debug!(%pamm, "Skipping denied pAMM");
                        continue;
                    }
                    tracing::info!(%pamm, "Serving auto-detected pAMM");
                    &*entry.insert(PriceLevelStreamConfig::auto_detected(
                        pamm.clone(),
                        self.auto_detected_gas_cost.clone(),
                    ))
                }
            };

            // Merge the frame's per-direction ladders into one entry per unordered token pair.
            let mut merged_pairs: HashMap<(Bytes, Bytes), (Vec<_>, Vec<_>)> = HashMap::new();
            for TitanPairLevels { token_in, token_out, order_book } in pairs {
                if !self.tokens.contains_key(&token_in) || !self.tokens.contains_key(&token_out) {
                    tracing::debug!(%token_in, %token_out, "Skipping pair with unknown token");
                    continue;
                }
                let sells_token0 = token_in < token_out;
                let key = if sells_token0 {
                    (token_in.clone(), token_out.clone())
                } else {
                    (token_out.clone(), token_in.clone())
                };
                let quotes = order_book
                    .into_iter()
                    .map(|TitanPriceLevel { amount_in, amount_out }| {
                        PriceLevelStreamQuote::new(amount_in, amount_out)
                    })
                    .collect();
                let entry = merged_pairs.entry(key).or_default();
                if sells_token0 {
                    entry.0 = quotes;
                } else {
                    entry.1 = quotes;
                }
            }

            for ((token0, token1), (quotes_0_to_1, quotes_1_to_0)) in merged_pairs {
                let id = component_id(&config.address, &token0, &token1);
                let id_string = id.to_string();
                let component = previous
                    .remove(&id_string)
                    .unwrap_or_else(|| {
                        let via_router = self
                            .router_venues
                            .contains(&config.address);
                        let component =
                            build_component(&self.tokens, config, id, &token0, &token1, via_router);
                        new_pairs.insert(id_string.clone(), component.clone());
                        component
                    });

                let state = PriceLevelStreamState::new(
                    token0,
                    token1,
                    quotes_0_to_1,
                    quotes_1_to_0,
                    config.gas_cost.clone(),
                );

                states.insert(id_string.clone(), Box::new(state));
                self.components
                    .insert(id_string, component);
            }
        }

        // Every re-emitted pair was moved back into `self.components` above — whatever remains
        // is gone: the pair, or its whole venue, is no longer streamed.
        let removed_pairs = previous;

        if states.is_empty() && new_pairs.is_empty() && removed_pairs.is_empty() {
            return None;
        }

        Some(
            // Quotes target the block currently being built, hence partial. Sync states stay
            // empty (like the RFQ path) because no full block header is available.
            Update::new(frame.block_number, states, new_pairs)
                .set_is_partial(true)
                .set_removed_pairs(removed_pairs),
        )
    }

    /// WARN for the first rejected frame of a streak, DEBUG for the rest.
    fn log_rejection(&mut self, rejection: Rejection, frame: &TitanPriceLevelMessage) {
        if self.rejecting {
            tracing::debug!(
                reason = rejection.as_str(),
                block_number = frame.block_number,
                timestamp = frame.timestamp,
                "Rejecting price level frame"
            );
            return;
        }
        self.rejecting = true;
        tracing::warn!(
            reason = rejection.as_str(),
            block_number = frame.block_number,
            timestamp = frame.timestamp,
            newest_block = self.newest_block,
            newest_timestamp = self.newest_timestamp,
            "Rejecting price level frame; further rejections logged at debug until a frame is \
             accepted"
        );
    }
}

fn build_component(
    tokens: &HashMap<Bytes, Token>,
    config: &PriceLevelStreamConfig,
    id: Bytes,
    token0: &Bytes,
    token1: &Bytes,
    via_router: bool,
) -> ProtocolComponent {
    let protocol_system =
        if via_router { config.fallback_protocol_system() } else { config.protocol_system() };
    ProtocolComponent::new(
        id,
        protocol_system.clone(),
        protocol_system,
        // Titan builds Ethereum L1 blocks; the stream carries no other chains.
        Chain::Ethereum,
        vec![tokens[token0].clone(), tokens[token1].clone()],
        vec![config.address.clone()],
        HashMap::from([(PAMM_ADDRESS_ATTRIBUTE.to_string(), config.address.clone())]),
        Bytes::default(),
        Utc::now().naive_utc(),
    )
}

/// The component identity of a (pAMM, pair) combination: `pamm ++ token0 ++ token1`.
fn component_id(pamm: &Bytes, token0: &Bytes, token1: &Bytes) -> Bytes {
    Bytes::from([pamm.as_ref(), token0.as_ref(), token1.as_ref()].concat())
}

#[cfg(test)]
mod tests {
    use std::{
        str::FromStr,
        time::{Duration, Instant},
    };

    use super::{
        super::{config::DEFAULT_AUTO_DETECTED_GAS_COST, test_support::*},
        *,
    };

    /// 2026-09-05 16:09:18 UTC, the first frame of the live capture.
    const BASE_WALL_NANOS: u64 = 1_788_624_558_000_000_000;

    /// A test clock: wall and monotonic time both start at zero offset from a fixed base. Tests
    /// must only ever ask for non-decreasing seconds, mirroring a monotonic clock.
    struct Clock {
        start: Instant,
    }

    impl Clock {
        fn new() -> Self {
            Self { start: Instant::now() }
        }

        fn at(&self, seconds: u64) -> Now {
            Now {
                wall_nanos: BASE_WALL_NANOS + seconds * NANOS_PER_SECOND,
                instant: self.start + Duration::from_secs(seconds),
            }
        }
    }

    fn tracker() -> SnapshotTracker {
        let config = PriceLevelStreamConfig::new(
            "fermiswap",
            Bytes::from_str(PAMM).unwrap(),
            BigUint::from(120_000u64),
        );
        SnapshotTracker::new(
            HashMap::from([(config.address.clone(), config)]),
            HashSet::new(),
            tokens(),
            false,
            BigUint::from(DEFAULT_AUTO_DETECTED_GAS_COST),
            HashSet::new(),
            DEFAULT_STALE_AFTER,
        )
    }

    fn level(amount_in: u64, amount_out: u64) -> TitanPriceLevel {
        TitanPriceLevel {
            amount_in: BigUint::from(amount_in),
            amount_out: BigUint::from(amount_out),
        }
    }

    fn pair_levels(
        token_in: &str,
        token_out: &str,
        order_book: Vec<TitanPriceLevel>,
    ) -> TitanPairLevels {
        TitanPairLevels {
            token_in: Bytes::from_str(token_in).unwrap(),
            token_out: Bytes::from_str(token_out).unwrap(),
            order_book,
        }
    }

    /// A frame built `seconds` after the base instant.
    fn message_at(
        block_number: u64,
        seconds: u64,
        pairs: Vec<TitanPairLevels>,
    ) -> TitanPriceLevelMessage {
        TitanPriceLevelMessage {
            block_number,
            timestamp: BASE_WALL_NANOS + seconds * NANOS_PER_SECOND,
            pamms: vec![TitanPammLevels { pamm: Bytes::from_str(PAMM).unwrap(), pairs }],
        }
    }

    fn message(block_number: u64, pairs: Vec<TitanPairLevels>) -> TitanPriceLevelMessage {
        message_at(block_number, 0, pairs)
    }

    fn wbtc_usdc_pairs() -> Vec<TitanPairLevels> {
        vec![
            pair_levels(WBTC, USDC, vec![level(100_000_000, 100_000_000_000)]),
            pair_levels(USDC, WBTC, vec![level(100_000_000_000, 99_000_000)]),
        ]
    }

    fn expected_id() -> String {
        // pamm ++ token0 ++ token1 with WBTC < USDC.
        format!("{PAMM}{}{}", &WBTC[2..], &USDC[2..])
    }

    #[test]
    fn first_snapshot_emits_new_pair_with_both_directions() {
        let clock = Clock::new();
        let mut tracker = tracker();
        let Update {
            block_number_or_timestamp,
            is_partial,
            sync_states,
            states,
            new_pairs,
            removed_pairs,
        } = tracker
            .on_frame(message(100, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");

        assert_eq!(block_number_or_timestamp, 100);
        assert!(is_partial);
        assert!(sync_states.is_empty());
        assert!(removed_pairs.is_empty());

        let id = expected_id();
        let component = &new_pairs[&id];
        assert_eq!(component.protocol_system, "pricelevelstream:fermiswap");
        assert_eq!(
            component.static_attributes[PAMM_ADDRESS_ATTRIBUTE],
            Bytes::from_str(PAMM).unwrap()
        );

        let PriceLevelStreamState {
            token0,
            token1,
            quotes_0_to_1,
            quotes_1_to_0,
            gas_cost,
            quotable_until: _,
        } = states[&id]
            .as_any()
            .downcast_ref::<PriceLevelStreamState>()
            .expect("price level state");
        assert_eq!(token0, &Bytes::from_str(WBTC).unwrap());
        assert_eq!(token1, &Bytes::from_str(USDC).unwrap());
        assert_eq!(quotes_0_to_1.len(), 1);
        assert_eq!(quotes_1_to_0.len(), 1);
        assert_eq!(quotes_0_to_1[0].amount_in, BigUint::from(100_000_000u64));
        assert_eq!(gas_cost, &BigUint::from(120_000u64));
    }

    #[test]
    fn repeated_snapshot_is_not_a_new_pair() {
        let clock = Clock::new();
        let mut tracker = tracker();
        tracker
            .on_frame(message(100, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");
        let update = tracker
            .on_frame(message(101, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");

        assert!(update.new_pairs.is_empty());
        assert!(update.removed_pairs.is_empty());
        assert!(update
            .states
            .contains_key(&expected_id()));
    }

    #[test]
    fn dropped_pair_is_removed() {
        let clock = Clock::new();
        let mut tracker = tracker();
        tracker
            .on_frame(message(100, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");
        let weth_usdc =
            vec![pair_levels(WETH, USDC, vec![level(1_000_000_000_000_000_000, 3_000_000_000)])];
        let update = tracker
            .on_frame(message(101, weth_usdc), clock.at(0))
            .expect("update expected");

        assert_eq!(update.removed_pairs.len(), 1);
        assert!(update
            .removed_pairs
            .contains_key(&expected_id()));
        assert_eq!(update.new_pairs.len(), 1);
        assert_eq!(update.states.len(), 1);
    }

    #[test]
    fn block_regression_is_rejected() {
        let clock = Clock::new();
        let mut tracker = tracker();
        tracker
            .on_frame(message_at(101, 0, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");

        let regressed =
            vec![pair_levels(WETH, USDC, vec![level(1_000_000_000_000_000_000, 3_000_000_000)])];
        assert!(tracker
            .on_frame(message_at(100, 1, regressed), clock.at(1))
            .is_none());

        let update = tracker
            .on_frame(message_at(102, 2, wbtc_usdc_pairs()), clock.at(2))
            .expect("update expected");
        assert!(update.new_pairs.is_empty());
    }

    #[test]
    fn data_exactly_stale_after_old_is_rejected() {
        let clock = Clock::new();
        let mut tracker = tracker();
        // Built at t=0, judged at t=24: exactly the window, already stale.
        assert!(tracker
            .on_frame(message_at(100, 0, wbtc_usdc_pairs()), clock.at(24))
            .is_none());
        // One second younger is accepted.
        assert!(tracker
            .on_frame(message_at(100, 1, wbtc_usdc_pairs()), clock.at(24))
            .is_some());
    }

    #[test]
    fn frame_from_the_future_is_rejected() {
        let clock = Clock::new();
        let mut tracker = tracker();
        assert!(tracker
            .on_frame(message_at(100, 13, wbtc_usdc_pairs()), clock.at(0))
            .is_none());
        assert!(tracker
            .on_frame(message_at(100, 12, wbtc_usdc_pairs()), clock.at(0))
            .is_some());
    }

    #[test]
    fn older_timestamp_frame_is_rejected() {
        let clock = Clock::new();
        let mut tracker = tracker();
        tracker
            .on_frame(message_at(100, 5, wbtc_usdc_pairs()), clock.at(5))
            .expect("update expected");
        assert!(tracker
            .on_frame(message_at(100, 4, wbtc_usdc_pairs()), clock.at(5))
            .is_none());
    }

    #[test]
    fn equal_timestamp_frame_is_accepted() {
        let clock = Clock::new();
        let mut tracker = tracker();
        tracker
            .on_frame(message_at(100, 5, wbtc_usdc_pairs()), clock.at(5))
            .expect("update expected");
        // Titan re-emits within a build round with the same timestamp and different content.
        let changed = vec![
            pair_levels(WBTC, USDC, vec![level(100_000_000, 101_000_000_000)]),
            pair_levels(USDC, WBTC, vec![level(100_000_000_000, 99_000_000)]),
        ];
        let update = tracker
            .on_frame(message_at(100, 5, changed), clock.at(5))
            .expect("update expected");
        assert!(update
            .states
            .contains_key(&expected_id()));
    }

    #[test]
    fn block_jump_beyond_the_elapsed_bound_is_rejected() {
        let clock = Clock::new();
        let mut tracker = tracker();
        tracker
            .on_frame(message_at(100, 0, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");
        // One second later the chain cannot have advanced by more than 0 + 2 blocks.
        assert!(tracker
            .on_frame(message_at(103, 1, wbtc_usdc_pairs()), clock.at(1))
            .is_none());
        assert!(tracker
            .on_frame(message_at(u64::MAX / 2, 1, wbtc_usdc_pairs()), clock.at(1))
            .is_none());
        // The tracker is not frozen: a plausible block is still accepted afterwards.
        assert!(tracker
            .on_frame(message_at(101, 2, wbtc_usdc_pairs()), clock.at(2))
            .is_some());
    }

    #[test]
    fn block_jump_within_the_elapsed_bound_is_accepted() {
        let clock = Clock::new();
        let mut tracker = tracker();
        tracker
            .on_frame(message_at(100, 0, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");
        // 60 s later: 60 / 12 + 2 = 7 blocks allowed.
        assert!(tracker
            .on_frame(message_at(107, 60, wbtc_usdc_pairs()), clock.at(60))
            .is_some());
    }

    #[test]
    fn first_frame_skips_the_block_checks() {
        let clock = Clock::new();
        let mut tracker = tracker();
        assert!(tracker
            .on_frame(message_at(25_912_232, 0, wbtc_usdc_pairs()), clock.at(0))
            .is_some());
    }

    #[test]
    fn rejections_are_counted_by_reason() {
        use metrics_util::debugging::DebuggingRecorder;

        use super::super::telemetry::{
            test_support::{counter_value, snapshot_map},
            FRAMES_ACCEPTED, FRAMES_REJECTED,
        };

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            let clock = Clock::new();
            let mut tracker = tracker();
            tracker.on_frame(message_at(100, 5, wbtc_usdc_pairs()), clock.at(5));
            // Still fresh (16 s old) but stamped before the accepted frame: out_of_order.
            tracker.on_frame(message_at(100, 4, wbtc_usdc_pairs()), clock.at(20));
            tracker.on_frame(message_at(100, 5, wbtc_usdc_pairs()), clock.at(29)); // too_old
            tracker.on_frame(message_at(100, 45, wbtc_usdc_pairs()), clock.at(29)); // in_future
            tracker.on_frame(message_at(99, 6, wbtc_usdc_pairs()), clock.at(29)); // block_regression
            tracker.on_frame(message_at(200, 6, wbtc_usdc_pairs()), clock.at(29)); // block_jump
        });
        let snapshot = snapshot_map(snapshotter.snapshot());
        assert_eq!(counter_value(&snapshot, FRAMES_ACCEPTED, &[]), 1);
        for reason in ["too_old", "in_future", "out_of_order", "block_regression", "block_jump"] {
            assert_eq!(
                counter_value(&snapshot, FRAMES_REJECTED, &[("reason", reason)]),
                1,
                "{reason}"
            );
        }
    }

    #[test]
    fn vanished_pamm_has_its_pairs_removed() {
        let clock = Clock::new();
        let mut tracker = tracker();
        tracker
            .on_frame(message(100, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");

        // The next frame no longer contains the pAMM at all: a complete snapshot without a
        // venue means the venue is gone, pairs and all.
        let update = tracker
            .on_frame(
                TitanPriceLevelMessage {
                    block_number: 101,
                    timestamp: BASE_WALL_NANOS,
                    pamms: vec![],
                },
                clock.at(0),
            )
            .expect("update expected");
        assert!(update.states.is_empty());
        assert!(update.new_pairs.is_empty());
        assert_eq!(update.removed_pairs.len(), 1);
        assert!(update
            .removed_pairs
            .contains_key(&expected_id()));

        // Nothing served and nothing changed: no update.
        assert!(tracker
            .on_frame(
                TitanPriceLevelMessage {
                    block_number: 102,
                    timestamp: BASE_WALL_NANOS,
                    pamms: vec![],
                },
                clock.at(0),
            )
            .is_none());

        // A venue that reappears is a new pair again.
        let update = tracker
            .on_frame(message(103, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");
        assert!(update
            .new_pairs
            .contains_key(&expected_id()));
    }

    #[test]
    fn unregistered_pamm_produces_no_update_without_auto_detection() {
        let clock = Clock::new();
        let mut tracker = SnapshotTracker::new(
            HashMap::new(),
            HashSet::new(),
            tokens(),
            false,
            BigUint::from(DEFAULT_AUTO_DETECTED_GAS_COST),
            HashSet::new(),
            DEFAULT_STALE_AFTER,
        );
        assert!(tracker
            .on_frame(message(100, wbtc_usdc_pairs()), clock.at(0))
            .is_none());
    }

    #[test]
    fn denied_pamm_is_not_auto_detected() {
        let clock = Clock::new();
        let denied = HashSet::from([Bytes::from_str(PAMM).unwrap()]);
        let mut tracker = SnapshotTracker::new(
            HashMap::new(),
            denied,
            tokens(),
            true,
            BigUint::from(DEFAULT_AUTO_DETECTED_GAS_COST),
            HashSet::new(),
            DEFAULT_STALE_AFTER,
        );
        assert!(tracker
            .on_frame(message(100, wbtc_usdc_pairs()), clock.at(0))
            .is_none());
    }

    #[test]
    fn auto_detected_pamm_is_served_under_its_address() {
        let clock = Clock::new();
        let mut tracker = SnapshotTracker::new(
            HashMap::new(),
            HashSet::new(),
            tokens(),
            true,
            BigUint::from(DEFAULT_AUTO_DETECTED_GAS_COST),
            HashSet::new(),
            DEFAULT_STALE_AFTER,
        );
        let update = tracker
            .on_frame(message(100, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");

        let component = &update.new_pairs[&expected_id()];
        assert_eq!(component.protocol_system, format!("pricelevelstream:{PAMM}"));
        let state = update.states[&expected_id()]
            .as_any()
            .downcast_ref::<PriceLevelStreamState>()
            .expect("price level state");
        assert_eq!(state.gas_cost, BigUint::from(DEFAULT_AUTO_DETECTED_GAS_COST));

        // The synthesized config is cached: the next snapshot is not a new pair again.
        let update = tracker
            .on_frame(message(101, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");
        assert!(update.new_pairs.is_empty());
    }

    #[test]
    fn auto_detected_gas_cost_override_applies() {
        let clock = Clock::new();
        let mut tracker = SnapshotTracker::new(
            HashMap::new(),
            HashSet::new(),
            tokens(),
            true,
            BigUint::from(42_000u64),
            HashSet::new(),
            DEFAULT_STALE_AFTER,
        );
        let update = tracker
            .on_frame(message(100, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");

        let state = update.states[&expected_id()]
            .as_any()
            .downcast_ref::<PriceLevelStreamState>()
            .expect("price level state");
        assert_eq!(state.gas_cost, BigUint::from(42_000u64));
    }

    /// A venue on the router's whitelist is emitted under `propammfallback:{name}`, so its swaps
    /// execute through Titan's PropAMMRouter; identity and attributes stay the same.
    #[test]
    fn whitelisted_venue_is_served_under_the_fallback_family() {
        let clock = Clock::new();
        let config = PriceLevelStreamConfig::new(
            "fermiswap",
            Bytes::from_str(PAMM).unwrap(),
            BigUint::from(120_000u64),
        );
        let mut tracker = SnapshotTracker::new(
            HashMap::from([(config.address.clone(), config)]),
            HashSet::new(),
            tokens(),
            false,
            BigUint::from(DEFAULT_AUTO_DETECTED_GAS_COST),
            HashSet::from([Bytes::from_str(PAMM).unwrap()]),
            DEFAULT_STALE_AFTER,
        );

        let update = tracker
            .on_frame(message(100, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");

        let component = &update.new_pairs[&expected_id()];
        assert_eq!(component.protocol_system, "propammfallback:fermiswap");
        assert_eq!(
            component.static_attributes[PAMM_ADDRESS_ATTRIBUTE],
            Bytes::from_str(PAMM).unwrap()
        );
    }

    /// The whitelist check is by address, so it also covers auto-detected, address-named venues.
    #[test]
    fn auto_detected_whitelisted_venue_is_served_under_the_fallback_family() {
        let clock = Clock::new();
        let mut tracker = SnapshotTracker::new(
            HashMap::new(),
            HashSet::new(),
            tokens(),
            true,
            BigUint::from(DEFAULT_AUTO_DETECTED_GAS_COST),
            HashSet::from([Bytes::from_str(PAMM).unwrap()]),
            DEFAULT_STALE_AFTER,
        );

        let update = tracker
            .on_frame(message(100, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");

        let component = &update.new_pairs[&expected_id()];
        assert_eq!(component.protocol_system, format!("propammfallback:{PAMM}"));
    }

    /// A venue absent from the whitelist keeps the direct `pricelevelstream:{name}` family — the
    /// router reverts `UnknownVenue` for it, which would send every swap to the Uniswap V3
    /// fallback.
    #[test]
    fn unwhitelisted_venue_keeps_the_direct_family() {
        let clock = Clock::new();
        let other_venue =
            Bytes::from_str("0x71e790dd841c8a9061487cb3e78c288e75ce0b3d").expect("valid address");
        let config = PriceLevelStreamConfig::new(
            "fermiswap",
            Bytes::from_str(PAMM).unwrap(),
            BigUint::from(120_000u64),
        );
        let mut tracker = SnapshotTracker::new(
            HashMap::from([(config.address.clone(), config)]),
            HashSet::new(),
            tokens(),
            false,
            BigUint::from(DEFAULT_AUTO_DETECTED_GAS_COST),
            HashSet::from([other_venue]),
            DEFAULT_STALE_AFTER,
        );

        let update = tracker
            .on_frame(message(100, wbtc_usdc_pairs()), clock.at(0))
            .expect("update expected");

        assert_eq!(update.new_pairs[&expected_id()].protocol_system, "pricelevelstream:fermiswap");
    }

    #[test]
    fn unknown_tokens_are_skipped() {
        let clock = Clock::new();
        let mut tracker = tracker();
        let unknown = vec![pair_levels(
            "0x1111111111111111111111111111111111111111",
            USDC,
            vec![level(1, 1)],
        )];
        assert!(tracker
            .on_frame(message(100, unknown), clock.at(0))
            .is_none());
    }
}
