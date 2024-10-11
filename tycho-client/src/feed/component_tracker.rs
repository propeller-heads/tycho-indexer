use crate::{rpc::RPCClient, RPCError};
use std::collections::{HashMap, HashSet};
use tracing::{debug, instrument, warn};
use tycho_core::{
    dto::{BlockChanges, Chain, ProtocolComponent, ProtocolComponentsRequestBody, ProtocolId},
    Bytes,
};

#[derive(Clone, Debug)]
pub(crate) enum ComponentFilterVariant {
    Ids(Vec<String>),
    /// MinimumTVLRange is a tuple of (remove_tvl_threshold, add_tvl_threshold). Components that
    /// drop below the remove threshold will be removed from tracking, components that exceed the
    /// add threshold will be added. This helps buffer against components that fluctuate on the
    /// tvl threshold boundary.
    MinimumTVLRange((f64, f64)),
}

#[derive(Clone, Debug)]
pub struct ComponentFilter {
    variant: ComponentFilterVariant,
}

impl ComponentFilter {
    #[allow(non_snake_case)] // for backwards compatibility
    #[deprecated(since = "0.9.2", note = "Please use with_tvl_range instead")]
    pub fn MinimumTVL(min_tvl: f64) -> ComponentFilter {
        ComponentFilter { variant: ComponentFilterVariant::MinimumTVLRange((min_tvl, min_tvl)) }
    }

    #[allow(non_snake_case)]
    pub fn with_tvl_range(remove_tvl_threshold: f64, add_tvl_threshold: f64) -> ComponentFilter {
        ComponentFilter {
            variant: ComponentFilterVariant::MinimumTVLRange((
                remove_tvl_threshold,
                add_tvl_threshold,
            )),
        }
    }

    #[deprecated(since = "0.9.2")]
    #[allow(non_snake_case)] // for backwards compatibility
    pub fn Ids(ids: Vec<String>) -> ComponentFilter {
        ComponentFilter { variant: ComponentFilterVariant::Ids(ids) }
    }
}

/// Helper struct to store which components are being tracked atm.
pub struct ComponentTracker<R: RPCClient> {
    chain: Chain,
    protocol_system: String,
    filter: ComponentFilter,
    // We will need to request a snapshot for components/Contracts that we did not emit as
    // snapshot for yet but are relevant now, e.g. because min tvl threshold exceeded.
    pub components: HashMap<String, ProtocolComponent>,
    /// derived from tracked components, we need this if subscribed to a vm extractor cause updates
    /// are emitted on a contract level instead of on a component level.
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
        }
    }
    /// Retrieve all components that belong to the system we are extracing and have sufficient tvl.
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
        self.update_contracts();
        Ok(())
    }

    fn update_contracts(&mut self) {
        self.contracts.extend(
            self.components
                .values()
                .flat_map(|comp| comp.contract_ids.iter().cloned()),
        );
    }

    /// Add a new component to be tracked
    #[instrument(skip(self, new_components))]
    pub async fn start_tracking(&mut self, new_components: &[&String]) -> Result<(), RPCError> {
        if new_components.is_empty() {
            return Ok(());
        }
        let request = ProtocolComponentsRequestBody::id_filtered(
            &self.protocol_system,
            new_components
                .iter()
                .map(|pc_id| pc_id.to_string())
                .collect(),
            self.chain,
        );

        self.components.extend(
            self.rpc_client
                .get_protocol_components(&request)
                .await?
                .protocol_components
                .into_iter()
                .map(|pc| (pc.id.clone(), pc)),
        );
        self.update_contracts();
        debug!(n_components = new_components.len(), "StartedTracking");
        Ok(())
    }

    /// Stop tracking components
    #[instrument(skip(self, to_remove))]
    pub fn stop_tracking<'a, I: IntoIterator<Item = &'a String> + std::fmt::Debug>(
        &mut self,
        to_remove: I,
    ) -> HashMap<String, ProtocolComponent> {
        let mut n_components = 0;
        let res = to_remove
            .into_iter()
            .filter_map(|k| {
                let comp = self.components.remove(k);
                if let Some(component) = &comp {
                    n_components += 1;
                    for contract in component.contract_ids.iter() {
                        self.contracts.remove(contract);
                    }
                }
                comp.map(|c| (k.clone(), c))
            })
            .collect();
        debug!(n_components, "StoppedTracking");
        res
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

    pub fn get_tracked_component_ids(&self) -> Vec<ProtocolId> {
        self.components
            .keys()
            .map(|k| ProtocolId { chain: self.chain, id: k.clone() })
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
    use crate::{
        feed::component_tracker::{ComponentFilter, ComponentTracker},
        rpc::MockRPCClient,
    };
    use tycho_core::{
        dto::{
            Chain, PaginationResponse, ProtocolComponent, ProtocolComponentRequestResponse,
            ProtocolId,
        },
        Bytes,
    };

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
        let exp = vec![ProtocolId { chain: Chain::Ethereum, id: "Component1".to_string() }];

        let res = tracker.get_tracked_component_ids();

        assert_eq!(res, exp);
    }
}
