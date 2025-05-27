use std::collections::{HashMap, HashSet};

use tracing::{debug, instrument, warn};
use tycho_common::{
    dto::{BlockChanges, Chain, DCIData, ProtocolComponent, ProtocolComponentsRequestBody},
    Bytes,
};

use crate::{rpc::RPCClient, RPCError};

#[derive(Clone, Debug)]
pub(crate) enum ComponentFilterVariant {
    Ids(Vec<String>),
    /// MinimumTVLRange is a tuple of (remove_tvl_threshold, add_tvl_threshold). Components that
    /// drop below the remove threshold will be removed from tracking, components that exceed the
    /// add threshold will be added. This helps buffer against components that fluctuate on the
    /// tvl threshold boundary. The thresholds are denominated in native token of the chain, for
    /// example 1 means 1 ETH on ethereum.
    MinimumTVLRange((f64, f64)),
}

#[derive(Clone, Debug)]
pub struct ComponentFilter {
    variant: ComponentFilterVariant,
}

impl ComponentFilter {
    /// Creates a `ComponentFilter` that filters components based on a minimum Total Value Locked
    /// (TVL) threshold.
    ///
    /// # Arguments
    ///
    /// * `min_tvl` - The minimum TVL required for a component to be tracked. This is denominated in
    ///   native token of the chain.
    #[allow(non_snake_case)] // for backwards compatibility
    #[deprecated(since = "0.9.2", note = "Please use with_tvl_range instead")]
    pub fn MinimumTVL(min_tvl: f64) -> ComponentFilter {
        ComponentFilter { variant: ComponentFilterVariant::MinimumTVLRange((min_tvl, min_tvl)) }
    }

    /// Creates a `ComponentFilter` with a specified TVL range for adding or removing components
    /// from tracking.
    ///
    /// Components that drop below the `remove_tvl_threshold` will be removed from tracking,
    /// while components that exceed the `add_tvl_threshold` will be added to tracking.
    /// This approach helps to reduce fluctuations caused by components hovering around a single
    /// threshold.
    ///
    /// # Arguments
    ///
    /// * `remove_tvl_threshold` - The TVL below which a component will be removed from tracking.
    /// * `add_tvl_threshold` - The TVL above which a component will be added to tracking.
    ///
    /// Note: thresholds are denominated in native token of the chain.
    pub fn with_tvl_range(remove_tvl_threshold: f64, add_tvl_threshold: f64) -> ComponentFilter {
        ComponentFilter {
            variant: ComponentFilterVariant::MinimumTVLRange((
                remove_tvl_threshold,
                add_tvl_threshold,
            )),
        }
    }

    /// Creates a `ComponentFilter` that **includes only** the components with the specified IDs,
    /// effectively filtering out all other components.
    ///
    /// # Arguments
    ///
    /// * `ids` - A vector of component IDs to include in the filter. Only components with these IDs
    ///   will be tracked.
    #[allow(non_snake_case)] // for backwards compatibility
    pub fn Ids(ids: Vec<String>) -> ComponentFilter {
        ComponentFilter { variant: ComponentFilterVariant::Ids(ids) }
    }
}

/// Helper struct to determine which components and contracts are being tracked atm.
pub struct ComponentTracker<R: RPCClient> {
    chain: Chain,
    protocol_system: String,
    filter: ComponentFilter,
    // We will need to request a snapshot for components/contracts that we did not emit as
    // snapshot for yet but are relevant now, e.g. because min tvl threshold exceeded.
    pub components: HashMap<String, ProtocolComponent>,
    /// Map of entrypoint id to a tuple of (set of component ids for components that have this
    /// entrypoint, set of detected contracts for the entrypoint)
    pub entrypoints: HashMap<String, (HashSet<String>, HashSet<Bytes>)>,
    /// Derived from tracked components. We need this if subscribed to a vm extractor because
    /// updates are emitted on a contract level instead of a component level.
    pub contracts: HashSet<Bytes>,
    /// Client to retrieve necessary protocol components from the rpc.
    rpc_client: R,
}

impl<R> ComponentTracker<R>
where
    R: RPCClient,
{
    pub fn new(chain: Chain, protocol_system: &str, filter: ComponentFilter, rpc: R) -> Self {
        Self {
            chain,
            protocol_system: protocol_system.to_string(),
            filter,
            components: Default::default(),
            contracts: Default::default(),
            rpc_client: rpc,
            entrypoints: Default::default(),
        }
    }

    /// Retrieves all components that belong to the system we are streaming that have sufficient
    /// tvl. Also detects which contracts are relevant for simulating on those components.
    pub async fn initialise_components(&mut self) -> Result<(), RPCError> {
        let body = match &self.filter.variant {
            ComponentFilterVariant::Ids(ids) => ProtocolComponentsRequestBody::id_filtered(
                &self.protocol_system,
                ids.clone(),
                self.chain,
            ),
            ComponentFilterVariant::MinimumTVLRange((_, upper_tvl_threshold)) => {
                ProtocolComponentsRequestBody::system_filtered(
                    &self.protocol_system,
                    Some(*upper_tvl_threshold),
                    self.chain,
                )
            }
        };
        self.components = self
            .rpc_client
            .get_protocol_components_paginated(&body, 500, 4)
            .await?
            .protocol_components
            .into_iter()
            .map(|pc| (pc.id.clone(), pc))
            .collect::<HashMap<_, _>>();

        self.initialise_contracts();

        Ok(())
    }

    /// Initialise the tracked contracts list from tracked components and their entrypoints
    fn initialise_contracts(&mut self) {
        // Add contracts from all tracked components
        self.contracts = self
            .components
            .values()
            .flat_map(|comp| comp.contract_ids.iter().cloned())
            .collect();

        // Add contracts from entrypoints that are linked to tracked components
        let tracked_component_ids = self
            .components
            .keys()
            .cloned()
            .collect::<HashSet<_>>();
        for (_, (components, contracts)) in self.entrypoints.iter() {
            if !components.is_disjoint(&tracked_component_ids) {
                self.contracts
                    .extend(contracts.iter().cloned());
            }
        }
    }

    /// Update the tracked contracts list with contracts associated with the given components
    fn update_contracts(&mut self, components: Vec<String>) {
        // Only process components that are actually being tracked. Convert to HashSet for
        // efficient lookup.
        let tracked_component_ids = components
            .iter()
            .filter(|&id| self.components.contains_key(id))
            .map(|s| s.to_string())
            .collect::<HashSet<_>>();

        // Add contracts from the components
        for comp in &tracked_component_ids {
            if let Some(component) = self.components.get(comp) {
                self.contracts
                    .extend(component.contract_ids.iter().cloned());
            }
        }

        // Identify entrypoints linked to the given components
        for (_, (components, contracts)) in self.entrypoints.iter() {
            if !components.is_disjoint(&tracked_component_ids) {
                self.contracts
                    .extend(contracts.iter().cloned());
            }
        }
    }

    /// Add a new component to be tracked
    #[instrument(skip(self, new_components))]
    pub async fn start_tracking(&mut self, new_components: &[&String]) -> Result<(), RPCError> {
        if new_components.is_empty() {
            return Ok(());
        }

        // Fetch the components
        let request = ProtocolComponentsRequestBody::id_filtered(
            &self.protocol_system,
            new_components
                .iter()
                .map(|&id| id.to_string())
                .collect(),
            self.chain,
        );
        let components = self
            .rpc_client
            .get_protocol_components(&request)
            .await?
            .protocol_components
            .into_iter()
            .map(|pc| (pc.id.clone(), pc))
            .collect::<HashMap<_, _>>();

        // Update components and contracts
        let component_ids: Vec<_> = components.keys().cloned().collect();
        let component_count = component_ids.len();
        self.components.extend(components);
        self.update_contracts(component_ids);

        debug!(n_components = component_count, "StartedTracking");
        Ok(())
    }

    /// Stop tracking components
    #[instrument(skip(self, to_remove))]
    pub fn stop_tracking<'a, I: IntoIterator<Item = &'a String> + std::fmt::Debug>(
        &mut self,
        to_remove: I,
    ) -> HashMap<String, ProtocolComponent> {
        let mut removed_components = HashMap::new();

        for component_id in to_remove {
            if let Some(component) = self.components.remove(component_id) {
                removed_components.insert(component_id.clone(), component);
            }
        }

        // Refresh the tracked contracts list. This is more reliable and efficient than directly
        // removing contracts from the list because some contracts are shared between components.
        self.initialise_contracts();

        debug!(n_components = removed_components.len(), "StoppedTracking");
        removed_components
    }

    /// Updates the tracked entrypoints and contracts based on the given DCI data.
    pub fn process_entrypoints(&mut self, dci_data: &DCIData) -> Result<(), RPCError> {
        // Update detected contracts for entrypoints
        for (entrypoint, traces) in &dci_data.trace_results {
            self.entrypoints
                .entry(entrypoint.clone())
                .or_insert_with(|| (HashSet::new(), HashSet::new()))
                .1
                .extend(traces.called_addresses.iter().cloned());
        }

        // Update linked components for entrypoints
        for (component, entrypoints) in &dci_data.new_entrypoints {
            for entrypoint in entrypoints {
                let (components, contracts) = self
                    .entrypoints
                    .entry(entrypoint.external_id.clone())
                    .or_insert_with(|| (HashSet::new(), HashSet::new()));
                components.insert(component.clone());
                // If the component is tracked, add the detected contracts to the tracker
                if self.components.contains_key(component) {
                    self.contracts
                        .extend(contracts.iter().cloned());
                }
            }
        }

        Ok(())
    }

    pub fn get_contracts_by_component<'a, I: IntoIterator<Item = &'a String>>(
        &self,
        ids: I,
    ) -> HashSet<Bytes> {
        ids.into_iter()
            .flat_map(|cid| {
                let comp = self
                    .components
                    .get(cid)
                    .unwrap_or_else(|| panic!("requested component that is not present: {cid}"));
                comp.contract_ids.iter().cloned()
            })
            .collect()
    }

    pub fn get_tracked_component_ids(&self) -> Vec<String> {
        self.components
            .keys()
            .cloned()
            .collect()
    }

    /// Given BlockChanges, filter out components that are no longer relevant and return the
    /// components that need to be added or removed.
    pub fn filter_updated_components(&self, deltas: &BlockChanges) -> (Vec<String>, Vec<String>) {
        match &self.filter.variant {
            ComponentFilterVariant::Ids(_) => (Default::default(), Default::default()),
            ComponentFilterVariant::MinimumTVLRange((remove_tvl, add_tvl)) => deltas
                .component_tvl
                .iter()
                .filter(|(_, &tvl)| tvl < *remove_tvl || tvl > *add_tvl)
                .map(|(id, _)| id.clone())
                .partition(|id| deltas.component_tvl[id] > *add_tvl),
        }
    }
}

#[cfg(test)]
mod test {
    use tycho_common::dto::{PaginationResponse, ProtocolComponentRequestResponse};

    use super::*;
    use crate::rpc::MockRPCClient;

    fn with_mocked_rpc() -> ComponentTracker<MockRPCClient> {
        let rpc = MockRPCClient::new();
        ComponentTracker::new(
            Chain::Ethereum,
            "uniswap-v2",
            ComponentFilter::with_tvl_range(0.0, 0.0),
            rpc,
        )
    }

    fn components_response() -> (Vec<Bytes>, ProtocolComponent) {
        let contract_ids = vec![Bytes::from("0x1234"), Bytes::from("0xbabe")];
        let component = ProtocolComponent {
            id: "Component1".to_string(),
            contract_ids: contract_ids.clone(),
            ..Default::default()
        };
        (contract_ids, component)
    }

    #[tokio::test]
    async fn test_initialise_components() {
        let mut tracker = with_mocked_rpc();
        let (contract_ids, component) = components_response();
        let exp_component = component.clone();
        tracker
            .rpc_client
            .expect_get_protocol_components_paginated()
            .returning(move |_, _, _| {
                Ok(ProtocolComponentRequestResponse {
                    protocol_components: vec![component.clone()],
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 1 },
                })
            });

        tracker
            .initialise_components()
            .await
            .expect("Retrieving components failed");

        assert_eq!(
            tracker
                .components
                .get("Component1")
                .expect("Component1 not tracked"),
            &exp_component
        );
        assert_eq!(tracker.contracts, contract_ids.into_iter().collect());
    }

    #[tokio::test]
    async fn test_start_tracking() {
        let mut tracker = with_mocked_rpc();
        let (contract_ids, component) = components_response();
        let exp_contracts = contract_ids.into_iter().collect();
        let component_id = component.id.clone();
        let components_arg = [&component_id];
        tracker
            .rpc_client
            .expect_get_protocol_components()
            .returning(move |_| {
                Ok(ProtocolComponentRequestResponse {
                    protocol_components: vec![component.clone()],
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 1 },
                })
            });

        tracker
            .start_tracking(&components_arg)
            .await
            .expect("Tracking components failed");

        assert_eq!(&tracker.contracts, &exp_contracts);
        assert!(tracker
            .components
            .contains_key("Component1"));
    }

    #[test]
    fn test_stop_tracking() {
        let mut tracker = with_mocked_rpc();
        let (contract_ids, component) = components_response();
        tracker
            .components
            .insert("Component1".to_string(), component.clone());
        tracker.contracts.extend(contract_ids);
        let components_arg = ["Component1".to_string(), "Component2".to_string()];
        let exp = [("Component1".to_string(), component)]
            .into_iter()
            .collect();

        let res = tracker.stop_tracking(&components_arg);

        assert_eq!(res, exp);
        assert!(tracker.contracts.is_empty());
    }

    #[test]
    fn test_get_contracts_by_component() {
        let mut tracker = with_mocked_rpc();
        let (exp_contracts, component) = components_response();
        tracker
            .components
            .insert("Component1".to_string(), component);
        let components_arg = ["Component1".to_string()];

        let res = tracker.get_contracts_by_component(&components_arg);

        assert_eq!(res, exp_contracts.into_iter().collect());
    }

    #[test]
    fn test_get_tracked_component_ids() {
        let mut tracker = with_mocked_rpc();
        let (_, component) = components_response();
        tracker
            .components
            .insert("Component1".to_string(), component);
        let exp = vec!["Component1".to_string()];

        let res = tracker.get_tracked_component_ids();

        assert_eq!(res, exp);
    }
}
