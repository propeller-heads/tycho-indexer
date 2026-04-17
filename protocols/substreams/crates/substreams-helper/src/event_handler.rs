use std::collections::HashMap;

use ethabi::ethereum_types::Address;
use substreams_ethereum::{
    pb::eth::v2::{self as eth},
    Event,
};

use crate::common::HasAddresser;

/// Utility struct to easily filter events and assign them handlers.
///
/// Usage:
/// ```
/// let eh = EventHandler::new(&block);
/// eh.filter_by_address(store); // This is optional, if omitted it will handle all events that match the type, independently of the emitting contract.
/// eh.on::<Transfer, _>(&mut on_transfer);
/// eh.on::<Approval, _>(&mut on_approval);
/// eh.on::<Mint, _>(&mut on_mint);
/// eh.on::<Burn, _>(&mut on_burn);
/// eh.handle_events(); // this will run all handlers
/// ```
///
/// You'll likely want to mutate some value from the handlers that is in the current scope.
/// For that, make your handlers be closures, that close over the variable you want to mutate, and
/// have the whole EventHandler block of code in its own scope (either by wrapping it in an aux
/// function or by wrapping it in {...})
///
/// Like so:
/// ```
/// let mut balances : Vec<Balance> = vec![];
/// {
///     let mut on_transfer = |/*...*/| {
///         // this handler modifies `balances`
///         balances.push(some_balance);
///     };
///     let eh = EventHandler::new(&block);
///     eh.on::<Transfer, _>(&mut on_transfer);
///     eh.handle_events();
/// }
///
/// // do whatever else with `balances` here.
/// ```
pub struct EventHandler<'a> {
    block: &'a eth::Block,
    #[allow(clippy::type_complexity)]
    handlers: HashMap<&'static str, Box<dyn FnMut(&eth::Log, &eth::TransactionTrace) + 'a>>,
    addresses: Option<Box<dyn HasAddresser + 'a>>,
}

impl<'a> EventHandler<'a> {
    pub fn new(block: &'a eth::Block) -> Self {
        Self { block, handlers: HashMap::new(), addresses: None }
    }

    /// Sets the HasAddresser as a filter for which events to handle.
    /// Only one at a time can be set. Setting it twice will remove the first one.
    /// Addresses found in the `HasAddresser` will be the ones we'll handle events from.
    pub fn filter_by_address(&mut self, addresser: impl HasAddresser + 'a) {
        self.addresses = Some(Box::new(addresser));
    }

    /// Registers a handler to be run on a given event. The handler should have the signature:
    /// `|ev: SomeEvent, tx: &pbeth::v2::TransactionTrace, log: &pbeth::v2::Log|`.
    /// You can only assign one handler to each Event type.
    /// Handlers are keyed by the name of the event they are handling, so be careful to not assign
    /// handlers for 2 different events named equal.
    pub fn on<E: Event, F>(&mut self, mut handler: F)
    where
        F: FnMut(E, &eth::TransactionTrace, &eth::Log) + 'a,
    {
        self.handlers.insert(
            E::NAME,
            Box::new(move |log: &eth::Log, tx: &eth::TransactionTrace| {
                if let Some(event) = E::match_and_decode(log) {
                    handler(event, tx, log);
                }
            }),
        );
    }

    /// Will run all registered handlers for all events present on the block that match the given
    /// filters. You'll likely want to run this just once.
    pub fn handle_events(&mut self) {
        // Here we don't need to filter out failed transactions because logs only exist for
        // successful ones.
        for log in self.block.logs() {
            if self.addresses.is_some() &&
                !&self
                    .addresses
                    .as_ref()
                    .unwrap()
                    .has_address(Address::from_slice(log.log.address.as_slice()))
            {
                continue;
            }

            for handler in self.handlers.values_mut() {
                handler(log.log, log.receipt.transaction);
            }
        }
    }
}
