use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use num_bigint::BigUint;
use tokio_stream::{Stream, StreamExt};
use tycho_common::{models::token::Token, Bytes};

use super::{
    config::{
        default_denied_pamms, default_served_pamms, PriceLevelStreamConfig,
        DEFAULT_AUTO_DETECTED_GAS_COST,
    },
    fallback_router::fetch_fallback_router_venues,
    titan::{self, ConnectionSettings, TITAN_PRICE_LEVEL_URL},
    tracker::{Now, SnapshotTracker, DEFAULT_STALE_AFTER},
};
use crate::protocol::models::Update;

/// Static attribute under which each emitted component carries its pAMM venue address.
pub const PAMM_ADDRESS_ATTRIBUTE: &str = "pamm_address";

/// Builds a stream of [`Update`]s from the Titan pAMM price level WebSocket.
///
/// A new builder serves no pAMMs: register the known venues via
/// [`with_known_pamms`](Self::with_known_pamms), individual ones via
/// [`add_pamm`](Self::add_pamm), or opt into serving unknown streamed venues via
/// [`auto_detect`](Self::auto_detect); [`with_tokens`](Self::with_tokens) provides the token
/// metadata pairs are interpreted with.
///
/// One component is emitted per (pAMM, token pair), identified by the concatenation
/// `pamm ++ token0 ++ token1` (tokens sorted ascending), under the protocol system
/// `pricelevelstream:{pamm}` — or `propammfallback:{pamm}` for venues on the PropAMMRouter
/// whitelist, unless [`without_fallback_router`](Self::without_fallback_router) turns that off.
/// The venue address is exposed through the [`PAMM_ADDRESS_ATTRIBUTE`] static attribute for
/// downstream encoding.
pub struct PriceLevelStreamBuilder {
    registry: HashMap<Bytes, PriceLevelStreamConfig>,
    denied: HashSet<Bytes>,
    tokens: HashMap<Bytes, Token>,
    url: Option<String>,
    auto_detect: bool,
    auto_detected_gas_cost: Option<BigUint>,
    connection: ConnectionSettings,
    /// Whether [`build`](Self::build) reads the PropAMMRouter whitelist and serves the venues on
    /// it under the `propammfallback:` family.
    fallback_router: bool,
}

impl Default for PriceLevelStreamBuilder {
    fn default() -> Self {
        Self {
            registry: HashMap::new(),
            denied: HashSet::new(),
            tokens: HashMap::new(),
            url: None,
            auto_detect: false,
            auto_detected_gas_cost: None,
            connection: ConnectionSettings::default(),
            fallback_router: true,
        }
    }
}

impl PriceLevelStreamBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables serving pAMMs that are not registered via
    /// [`with_known_pamms`](Self::with_known_pamms) or [`add_pamm`](Self::add_pamm)
    /// (disabled by default).
    ///
    /// When enabled, any unknown streamed venue — except denied ones (see
    /// [`deny_pamm`](Self::deny_pamm)) — is served under its full lowercase hex address
    /// as the name, with the default gas cost. A venue's protocol system therefore changes from
    /// the address form (`pricelevelstream:{0xaddress}`) to a name (`pricelevelstream:{name}`)
    /// once it gets registered — via [`add_pamm`](Self::add_pamm) or a release's
    /// [`default_served_pamms`] recognizing it; the name-independent identifiers — the component id
    /// and the [`PAMM_ADDRESS_ATTRIBUTE`] — stay stable across such renames.
    pub fn auto_detect(mut self, enabled: bool) -> Self {
        self.auto_detect = enabled;
        self
    }

    /// Overrides the per-swap gas cost that auto-detected pAMMs (see
    /// [`auto_detect`](Self::auto_detect)) are served with. Defaults to the maximum over the
    /// known venue profiles, as the conservative choice. Registered venues are unaffected —
    /// their gas cost comes from their [`PriceLevelStreamConfig`].
    pub fn auto_detected_gas_cost(mut self, gas_cost: BigUint) -> Self {
        self.auto_detected_gas_cost = Some(gas_cost);
        self
    }

    /// Overrides the stream endpoint, e.g. to connect to a closer Titan region than the default
    /// (see <https://docs.titanbuilder.xyz/propamms/takers>).
    pub fn endpoint(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Overrides how long a single connection attempt may take before it is aborted and retried
    /// (default: 10s), so a hung TCP/TLS handshake cannot block the stream forever.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connection.connect_timeout = timeout;
        self
    }

    /// Overrides the longest gap between Titan messages tolerated before the connection is
    /// treated as dead and re-established (default: 30s). Titan pushes several updates per
    /// second, so a multi-second silence means a stalled or half-open connection.
    pub fn read_idle_timeout(mut self, timeout: Duration) -> Self {
        self.connection.read_idle_timeout = timeout;
        self
    }

    /// Overrides the cap on the exponential reconnect backoff of `2^attempt` seconds
    /// (default: 32s).
    pub fn max_backoff(mut self, max_backoff: Duration) -> Self {
        self.connection.max_backoff = max_backoff;
        self
    }

    /// Registers a pAMM to be served under the given configuration, overriding any default,
    /// denied, or auto-detected one for the same address.
    ///
    /// Between [`add_pamm`](Self::add_pamm) and [`deny_pamm`](Self::deny_pamm) for the same
    /// address, the later call wins; the defaults applied by
    /// [`with_known_pamms`](Self::with_known_pamms) never override either, in any call order.
    pub fn add_pamm(mut self, config: PriceLevelStreamConfig) -> Self {
        self.denied.remove(&config.address);
        self.registry
            .insert(config.address.clone(), config);
        self
    }

    /// Excludes a venue from being served: drops its current registration (default or explicit)
    /// and blocks auto-detecting it.
    ///
    /// Between [`add_pamm`](Self::add_pamm) and [`deny_pamm`](Self::deny_pamm) for the same
    /// address, the later call wins; the defaults applied by
    /// [`with_known_pamms`](Self::with_known_pamms) never override either, in any call order —
    /// so denying a venue from the default set works whether the denial comes before or after
    /// [`with_known_pamms`](Self::with_known_pamms).
    pub fn deny_pamm(mut self, address: Bytes) -> Self {
        self.registry.remove(&address);
        self.denied.insert(address);
        self
    }

    /// Applies what is known about the streamed venues: registers the known-good ones
    /// ([`default_served_pamms`]) to be served and denies the known-bad ones
    /// ([`default_denied_pamms`]) — venues that stream quotes but whose swaps are not executable.
    ///
    /// These defaults never override an explicit [`add_pamm`](Self::add_pamm) or
    /// [`deny_pamm`](Self::deny_pamm) for the same address, regardless of call order.
    pub fn with_known_pamms(mut self) -> Self {
        for config in default_served_pamms() {
            if self.denied.contains(&config.address) {
                continue;
            }
            self.registry
                .entry(config.address.clone())
                .or_insert(config);
        }
        for address in default_denied_pamms() {
            if self.registry.contains_key(&address) {
                continue;
            }
            self.denied.insert(address);
        }
        self
    }

    /// Provides the token metadata used to build components and interpret amounts. Pairs whose
    /// tokens are missing here are skipped.
    pub fn with_tokens(mut self, tokens: HashMap<Bytes, Token>) -> Self {
        self.tokens = tokens;
        self
    }

    /// Keeps every venue on the direct `pricelevelstream:{name}` path, so swaps execute on the
    /// venues themselves and a stale maker quote reverts the route.
    ///
    /// By default [`build`](Self::build) emits venues on Titan's PropAMMRouter whitelist under
    /// `propammfallback:{name}` instead, so tycho-execution routes their swaps through the
    /// router. Opt out when the direct call is what you want to measure or execute, or to skip
    /// the whitelist read at startup.
    pub fn without_fallback_router(mut self) -> Self {
        self.fallback_router = false;
        self
    }

    /// Consumes the builder and opens the stream.
    ///
    /// Venues on Titan's PropAMMRouter whitelist are served under `propammfallback:{name}`, so
    /// tycho-execution routes their swaps through the router. The router falls back to a
    /// single-hop Uniswap V3 pool when the venue reverts — which a stale maker quote does in any
    /// simulation against a mined block. Only whitelisted venues may use the family: the router
    /// reverts `UnknownVenue` for others, so every swap would execute on the Uniswap V3 fallback
    /// at a worse price than the venue gives.
    ///
    /// Reading that whitelist needs a node at `RPC_URL` (from the environment, falling back to
    /// `.env`), and degrades instead of failing: without the variable, or when the read fails, a
    /// warning is logged and every venue stays on the direct `pricelevelstream:` path.
    /// [`without_fallback_router`](Self::without_fallback_router) skips the read and takes the
    /// direct path unconditionally.
    ///
    /// The whitelist is read once, on the first poll, and never re-read — it is governance-gated
    /// and changes rarely, and renaming a running component's protocol system would churn every
    /// consumer's component set. Restart the stream to pick up a whitelist change.
    ///
    /// The connection is established lazily on first poll and maintained (with reconnects) for as
    /// long as the stream is polled; it never terminates on its own, and dropping the stream
    /// closes the connection. Frames that contain no served pAMM produce no update.
    ///
    /// Each streamed frame is a complete snapshot of everything Titan currently streams, so
    /// every update carries the full set of the frame's pair states, with `new_pairs` /
    /// `removed_pairs` derived by diffing against the previous frame — a pair (or a whole
    /// venue) the stream stops serving is removed. Frames older than an already processed one
    /// are skipped, so updates never move backwards in block number. Pairs whose tokens are
    /// missing from the provided token metadata are skipped.
    pub fn build(self) -> impl Stream<Item = Update> + Send {
        let Self {
            registry,
            denied,
            tokens,
            url,
            auto_detect,
            auto_detected_gas_cost,
            connection,
            fallback_router,
        } = self;
        if registry.is_empty() && !auto_detect {
            tracing::warn!(
                "No pAMMs registered and auto-detection is off; the stream will never produce \
                 an update"
            );
        }
        if tokens.is_empty() {
            tracing::warn!(
                "No token metadata provided; every streamed pair will be skipped and the stream \
                 will never produce an update"
            );
        }
        let url = url.unwrap_or_else(|| TITAN_PRICE_LEVEL_URL.to_string());
        let auto_detected_gas_cost =
            auto_detected_gas_cost.unwrap_or_else(|| BigUint::from(DEFAULT_AUTO_DETECTED_GAS_COST));

        futures::FutureExt::flatten_stream(async move {
            let router_venues = if fallback_router {
                fetch_router_venues(rpc_url_from_env()).await
            } else {
                HashSet::new()
            };
            let mut tracker = SnapshotTracker::new(
                registry,
                denied,
                tokens,
                auto_detect,
                auto_detected_gas_cost,
                DEFAULT_STALE_AFTER,
                fallback_router,
            );
            tracker.set_router_venues(router_venues);

            titan::messages(url, connection)
                .filter_map(move |message| tracker.on_frame(message, Now::current()))
        })
    }
}

/// The node URL the whitelist is read from: `RPC_URL` from the environment, falling back to
/// `.env`.
fn rpc_url_from_env() -> Option<String> {
    std::env::var("RPC_URL")
        .ok()
        .or_else(|| {
            dotenv::dotenv().ok()?;
            std::env::var("RPC_URL").ok()
        })
}

/// The PropAMMRouter's whitelisted venues, or an empty set when they cannot be read — no node
/// URL, or a failed call. Both cases warn and leave every venue on the direct path, so a
/// misconfigured deployment loses the Uniswap V3 fallback instead of losing the stream.
async fn fetch_router_venues(rpc_url: Option<String>) -> HashSet<Bytes> {
    let Some(rpc_url) = rpc_url else {
        tracing::warn!(
            "RPC_URL is not set; pAMM swaps execute on the venues directly, without the \
             PropAMMRouter's Uniswap V3 fallback"
        );
        return HashSet::new();
    };

    match fetch_fallback_router_venues(&rpc_url).await {
        Ok(venues) => venues.into_iter().collect(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Could not read the PropAMMRouter venue whitelist; pAMM swaps execute on the \
                 venues directly, without the Uniswap V3 fallback"
            );
            HashSet::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{
        super::{config::default_denied_pamms, test_support::PAMM},
        *,
    };

    #[test]
    fn explicit_add_and_deny_are_last_wins() {
        let address = Bytes::from_str(PAMM).unwrap();
        let custom =
            || PriceLevelStreamConfig::new("custom", Bytes::from_str(PAMM).unwrap(), 1u64.into());

        let builder = PriceLevelStreamBuilder::new()
            .add_pamm(custom())
            .deny_pamm(address.clone());
        assert!(!builder.registry.contains_key(&address));
        assert!(builder.denied.contains(&address));

        let builder = PriceLevelStreamBuilder::new()
            .deny_pamm(address.clone())
            .add_pamm(custom());
        assert_eq!(builder.registry[&address].protocol, "custom");
        assert!(builder.denied.is_empty());
    }

    #[test]
    fn defaults_never_override_explicit_calls() {
        // Denying a venue from the default set works in either call order.
        let fermiswap_router = Bytes::from_str(PAMM).unwrap();
        for builder in [
            PriceLevelStreamBuilder::new()
                .deny_pamm(fermiswap_router.clone())
                .with_known_pamms(),
            PriceLevelStreamBuilder::new()
                .with_known_pamms()
                .deny_pamm(fermiswap_router.clone()),
        ] {
            assert!(!builder
                .registry
                .contains_key(&fermiswap_router));
            assert!(builder
                .denied
                .contains(&fermiswap_router));
            // The other defaults are unaffected.
            assert!(!builder.registry.is_empty());
        }

        // Registering a venue from the default deny set works in either call order.
        let denied_venue = default_denied_pamms().remove(0);
        let custom = || PriceLevelStreamConfig::new("custom", denied_venue.clone(), 1u64.into());
        for builder in [
            PriceLevelStreamBuilder::new()
                .add_pamm(custom())
                .with_known_pamms(),
            PriceLevelStreamBuilder::new()
                .with_known_pamms()
                .add_pamm(custom()),
        ] {
            assert_eq!(builder.registry[&denied_venue].protocol, "custom");
            assert!(!builder.denied.contains(&denied_venue));
        }
    }

    #[test]
    fn with_known_pamms_registers_known_venues() {
        // PAMM is the FermiSwap router, one of the default venues.
        let fermiswap_router = Bytes::from_str(PAMM).unwrap();

        let builder = PriceLevelStreamBuilder::new();
        assert!(builder.registry.is_empty());
        assert!(builder.denied.is_empty());

        let builder = builder.with_known_pamms();
        assert_eq!(builder.registry[&fermiswap_router].protocol, "fermiswap");
        // The known-bad venues get denied alongside, and never overlap the served defaults.
        assert!(!builder.denied.is_empty());
        assert!(builder.denied.is_disjoint(
            &builder
                .registry
                .keys()
                .cloned()
                .collect()
        ));

        // An `add_pamm` entry wins over the default for the same address, in either call order.
        let custom =
            || PriceLevelStreamConfig::new("custom", fermiswap_router.clone(), BigUint::from(1u64));
        for builder in [
            PriceLevelStreamBuilder::new()
                .add_pamm(custom())
                .with_known_pamms(),
            PriceLevelStreamBuilder::new()
                .with_known_pamms()
                .add_pamm(custom()),
        ] {
            assert_eq!(builder.registry[&fermiswap_router].protocol, "custom");
            assert_eq!(builder.registry[&fermiswap_router].gas_cost, BigUint::from(1u64));
        }
    }

    /// The PropAMMRouter path is the default; `without_fallback_router` is the way off it.
    #[test]
    fn fallback_router_is_on_unless_opted_out() {
        assert!(PriceLevelStreamBuilder::new().fallback_router);
        assert!(
            !PriceLevelStreamBuilder::new()
                .without_fallback_router()
                .fallback_router
        );
    }

    /// Without a node URL there is nothing to read the whitelist from: every venue stays on the
    /// direct path instead of the build failing.
    #[tokio::test]
    async fn missing_rpc_url_leaves_every_venue_on_the_direct_path() {
        assert!(fetch_router_venues(None)
            .await
            .is_empty());
    }

    /// A failed whitelist read degrades the same way as a missing node URL.
    #[tokio::test]
    async fn failed_whitelist_read_leaves_every_venue_on_the_direct_path() {
        assert!(fetch_router_venues(Some("not a url".to_string()))
            .await
            .is_empty());
    }

    /// The families this stream emits are the ones tycho-execution resolves an encoder for. A
    /// drift between the two makes every route through a pAMM fail to encode.
    #[test]
    fn families_match_the_execution_side_prefixes() {
        use tycho_execution::encoding::evm::{PRICE_LEVEL_STREAM_PREFIX, PROPAMM_FALLBACK_PREFIX};

        use super::super::config::{PRICE_LEVEL_STREAM_FAMILY, PROPAMM_FALLBACK_FAMILY};

        assert_eq!(format!("{PRICE_LEVEL_STREAM_FAMILY}:"), PRICE_LEVEL_STREAM_PREFIX);
        assert_eq!(format!("{PROPAMM_FALLBACK_FAMILY}:"), PROPAMM_FALLBACK_PREFIX);
    }
}
