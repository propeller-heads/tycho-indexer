use std::collections::{HashMap, HashSet};

use tracing::{debug, instrument, warn};
use tycho_common::{
    dto::{BlockChanges, Chain, DCIUpdate, ProtocolComponent, ProtocolComponentsRequestBody},
    models::{Address, ComponentId, ProtocolSystem},
};

use crate::{rpc::RPCClient, RPCError};

#[derive(Clone, Debug)]
pub(crate) enum ComponentFilterVariant {
    Ids(Vec<ComponentId>),
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
    pub fn Ids(ids: Vec<ComponentId>) -> ComponentFilter {
        ComponentFilter {
            variant: ComponentFilterVariant::Ids(
                ids.into_iter()
                    .map(|id| id.to_lowercase())
                    .collect(),
            ),
        }
    }
}

/// Information about an entrypoint, including which components use it and what contracts it
/// interacts with
#[derive(Default)]
struct EntrypointRelations {
    /// Set of component ids for components that have this entrypoint
    components: HashSet<ComponentId>,
    /// Set of detected contracts for the entrypoint
    contracts: HashSet<Address>,
}

/// Helper struct to determine which components and contracts are being tracked atm.
pub struct ComponentTracker<R: RPCClient> {
    chain: Chain,
    protocol_system: ProtocolSystem,
    filter: ComponentFilter,
    // We will need to request a snapshot for components/contracts that we did not emit as
    // snapshot for yet but are relevant now, e.g. because min tvl threshold exceeded.
    pub components: HashMap<ComponentId, ProtocolComponent>,
    /// Map of entrypoint id to its associated components and contracts
    entrypoints: HashMap<String, EntrypointRelations>,
    /// Derived from tracked components. We need this if subscribed to a vm extractor because
    /// updates are emitted on a contract level instead of a component level.
    pub contracts: HashSet<Address>,
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

        self.reinitialize_contracts();

        Ok(())
    }

    /// Initialise the tracked contracts list from tracked components and their entrypoints
    fn reinitialize_contracts(&mut self) {
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
        for entrypoint in self.entrypoints.values() {
            if !entrypoint
                .components
                .is_disjoint(&tracked_component_ids)
            {
                self.contracts
                    .extend(entrypoint.contracts.iter().cloned());
            }
        }
    }

    /// Update the tracked contracts list with contracts associated with the given components
    fn update_contracts(&mut self, components: Vec<ComponentId>) {
        // Only process components that are actually being tracked. Convert to HashSet for
        // efficient lookup.
        let tracked_component_ids = components
            .into_iter()
            .filter(|id| self.components.contains_key(id))
            .collect::<HashSet<_>>();

        // Add contracts from the components
        for comp in &tracked_component_ids {
            let component = self
                .components
                .get(comp)
                .expect("Component should exist as it was filtered above");
            self.contracts
                .extend(component.contract_ids.iter().cloned());
        }

        // Identify entrypoints linked to the given components
        for entrypoint in self.entrypoints.values() {
            if !entrypoint
                .components
                .is_disjoint(&tracked_component_ids)
            {
                self.contracts
                    .extend(entrypoint.contracts.iter().cloned());
            }
        }
    }

    /// Add new components to be tracked
    #[instrument(skip(self, new_components))]
    pub async fn start_tracking(
        &mut self,
        new_components: &[&ComponentId],
    ) -> Result<(), RPCError> {
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
    pub fn stop_tracking<'a, I: IntoIterator<Item = &'a ComponentId> + std::fmt::Debug>(
        &mut self,
        to_remove: I,
    ) -> HashMap<ComponentId, ProtocolComponent> {
        let mut removed_components = HashMap::new();

        for component_id in to_remove {
            if let Some(component) = self.components.remove(component_id) {
                removed_components.insert(component_id.clone(), component);
            }
        }

        // Refresh the tracked contracts list. This is more reliable and efficient than directly
        // removing contracts from the list because some contracts are shared between components.
        self.reinitialize_contracts();

        debug!(n_components = removed_components.len(), "StoppedTracking");
        removed_components
    }

    /// Updates the tracked entrypoints and contracts based on the given DCI data.
    pub fn process_entrypoints(&mut self, dci_update: &DCIUpdate) {
        // Update detected contracts for entrypoints
        for (entrypoint, traces) in &dci_update.trace_results {
            self.entrypoints
                .entry(entrypoint.clone())
                .or_default()
                .contracts
                .extend(traces.accessed_slots.keys().cloned());
        }

        // Update linked components for entrypoints
        for (component, entrypoints) in &dci_update.new_entrypoints {
            for entrypoint in entrypoints {
                let entrypoint_info = self
                    .entrypoints
                    .entry(entrypoint.external_id.clone())
                    .or_default();
                entrypoint_info
                    .components
                    .insert(component.clone());
                // If the component is tracked, add the detected contracts to the tracker
                if self.components.contains_key(component) {
                    self.contracts.extend(
                        entrypoint_info
                            .contracts
                            .iter()
                            .cloned(),
                    );
                }
            }
        }
    }

    /// Get related contracts for the given component ids. Assumes that the components are already
    /// tracked, either by calling `start_tracking` or `initialise_components`.
    ///
    /// # Arguments
    ///
    /// * `ids` - A vector of component IDs to get the contracts for.
    ///
    /// # Returns
    ///
    /// A HashSet of contract IDs. Components that are not tracked will be logged and skipped.
    pub fn get_contracts_by_component<'a, I: IntoIterator<Item = &'a String>>(
        &self,
        ids: I,
    ) -> HashSet<Address> {
        ids.into_iter()
            .filter_map(|cid| {
                if let Some(comp) = self.components.get(cid) {
                    // Collect contracts from all entrypoints linked to this component
                    let dci_contracts: HashSet<Address> = self
                        .entrypoints
                        .values()
                        .filter(|ep| ep.components.contains(cid))
                        .flat_map(|ep| ep.contracts.iter().cloned())
                        .collect();
                    Some(
                        comp.contract_ids
                            .clone()
                            .into_iter()
                            .chain(dci_contracts)
                            .collect::<HashSet<_>>(),
                    )
                } else {
                    warn!(
                        "Requested component is not tracked: {cid}. Skipping fetching contracts..."
                    );
                    None
                }
            })
            .flatten()
            .collect()
    }

    pub fn get_tracked_component_ids(&self) -> Vec<ComponentId> {
        self.components
            .keys()
            .cloned()
            .collect()
    }

    /// Given BlockChanges, filter out components that are no longer relevant and return the
    /// components that need to be added or removed.
    pub fn filter_updated_components(
        &self,
        deltas: &BlockChanges,
    ) -> (Vec<ComponentId>, Vec<ComponentId>) {
        let mut to_add = Vec::new();
        let mut to_remove = Vec::new();

        // Handle paused/unpaused components
        for (id, s) in &deltas.state_updates {
            // If the component is unpaused, we need to add it
            if s.deleted_attributes.contains("paused") {
                to_add.push(id.clone());
            }
            // If the component is paused, we need to remove it
            else if s
                .updated_attributes
                .contains_key("paused")
            {
                to_remove.push(id.clone());
            }
        }

        match &self.filter.variant {
            ComponentFilterVariant::Ids(_) => (to_add, to_remove),
            ComponentFilterVariant::MinimumTVLRange((remove_tvl, add_tvl)) => {
                let (tvl_add, tvl_remove): (Vec<_>, Vec<_>) = deltas
                    .component_tvl
                    .iter()
                    .filter(|(_, &tvl)| tvl < *remove_tvl || tvl > *add_tvl)
                    .map(|(id, _)| id.clone())
                    .partition(|id| deltas.component_tvl[id] > *add_tvl);

                to_add.extend(tvl_add);
                to_remove.extend(tvl_remove);
                (to_add, to_remove)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use tycho_common::{
        dto::{PaginationResponse, ProtocolComponentRequestResponse},
        Bytes,
    };

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

    fn components_response() -> (Vec<Address>, ProtocolComponent) {
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

    #[test]
    fn test_filter_updated_components_paused() {
        use std::collections::HashMap;

        use tycho_common::dto::{BlockChanges, ProtocolStateDelta};

        let tracker = with_mocked_rpc();

        // Create test deltas with paused/unpaused components
        let mut state_updates = HashMap::new();

        // Component1: gets paused (added to updated_attributes)
        state_updates.insert(
            "Component1".to_string(),
            ProtocolStateDelta {
                component_id: "Component1".to_string(),
                updated_attributes: [("paused".to_string(), Bytes::from("0x01"))]
                    .into_iter()
                    .collect(),
                deleted_attributes: Default::default(),
            },
        );

        // Component2: gets unpaused (paused removed from deleted_attributes)
        state_updates.insert(
            "Component2".to_string(),
            ProtocolStateDelta {
                component_id: "Component2".to_string(),
                updated_attributes: Default::default(),
                deleted_attributes: ["paused".to_string()]
                    .into_iter()
                    .collect(),
            },
        );

        let deltas = BlockChanges { state_updates, ..Default::default() };

        let (to_add, to_remove) = tracker.filter_updated_components(&deltas);

        assert_eq!(to_add, vec!["Component2".to_string()]);
        assert_eq!(to_remove, vec!["Component1".to_string()]);
    }

    #[test]
    fn test_filter_updated_components_tvl_and_paused() {
        use std::collections::HashMap;

        use tycho_common::dto::{BlockChanges, ProtocolStateDelta};

        let tracker = ComponentTracker::new(
            Chain::Ethereum,
            "uniswap-v2",
            ComponentFilter::with_tvl_range(50.0, 100.0),
            MockRPCClient::new(),
        );

        // Create test deltas with both TVL changes and paused state changes
        let mut state_updates = HashMap::new();

        // Component1: gets paused
        state_updates.insert(
            "Component1".to_string(),
            ProtocolStateDelta {
                component_id: "Component1".to_string(),
                updated_attributes: [("paused".to_string(), Bytes::from("0x01"))]
                    .into_iter()
                    .collect(),
                deleted_attributes: Default::default(),
            },
        );

        // Component2: gets unpaused
        state_updates.insert(
            "Component2".to_string(),
            ProtocolStateDelta {
                component_id: "Component2".to_string(),
                updated_attributes: Default::default(),
                deleted_attributes: ["paused".to_string()]
                    .into_iter()
                    .collect(),
            },
        );

        let component_tvl = [
            ("Component3".to_string(), 150.0), // Above add threshold
            ("Component4".to_string(), 25.0),  // Below remove threshold
        ]
        .into_iter()
        .collect();

        let deltas = BlockChanges { state_updates, component_tvl, ..Default::default() };

        let (to_add, to_remove) = tracker.filter_updated_components(&deltas);

        // Should include both paused/unpaused components and TVL-based changes
        assert!(to_add.contains(&"Component2".to_string())); // unpaused
        assert!(to_add.contains(&"Component3".to_string())); // high TVL
        assert!(to_remove.contains(&"Component1".to_string())); // paused
        assert!(to_remove.contains(&"Component4".to_string())); // low TVL
    }
}
