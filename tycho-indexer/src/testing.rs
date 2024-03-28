use mockall::mock;
use std::collections::HashMap;

use async_trait::async_trait;
use chrono::NaiveDateTime;
#[cfg(test)]
use ethers::types::U256;
use tycho_core::{
    models::{
        blockchain::{Block, Transaction},
        contract::{Contract, ContractDelta},
        protocol::{
            ComponentBalance, ProtocolComponent, ProtocolComponentState,
            ProtocolComponentStateDelta,
        },
        token::CurrencyToken,
        Address, Chain, ContractId, ExtractionState, PaginationParams, ProtocolType, TxHash,
    },
    storage::{
        BlockIdentifier, BlockOrTimestamp, ChainGateway, ContractStateGateway,
        ExtractionStateGateway, Gateway, ProtocolGateway, StorageError, Version,
    },
    Bytes,
};

mock! {
    pub Gateway {}
    #[async_trait]
    impl ExtractionStateGateway for Gateway {
        async fn get_state(&self, name: &str, chain: &Chain) -> Result<ExtractionState, StorageError>;
        async fn save_state(&self, state: &ExtractionState) -> Result<(), StorageError>;
    }

    #[async_trait]
    impl ChainGateway for Gateway {
        async fn upsert_block(&self, new: &[Block]) -> Result<(), StorageError>;
        async fn get_block(&self, id: &BlockIdentifier) -> Result<Block, StorageError>;
        async fn upsert_tx(&self, new: &[Transaction]) -> Result<(), StorageError>;
        async fn get_tx(&self, hash: &TxHash) -> Result<Transaction, StorageError>;
        async fn revert_state(&self, to: &BlockIdentifier) -> Result<(), StorageError>;
    }

    impl ContractStateGateway for Gateway {
        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn get_contract<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            id: &'life1 ContractId,
            version: Option<&'life2 Version>,
            include_slots: bool,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<Contract, StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn get_contracts<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            addresses: Option<&'life2 [Address]>,
            version: Option<&'life3 Version>,
            include_slots: bool,
            retrieve_balances: bool,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<Vec<Contract>, StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn insert_contract<'life0, 'life1, 'async_trait>(
            &'life0 self,
            new: &'life1 Contract,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<(), StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn update_contracts<'life0, 'life1, 'async_trait>(
            &'life0 self,
            new: &'life1 [(TxHash, ContractDelta)],
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<(), StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn delete_contract<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            id: &'life1 ContractId,
            at_tx: &'life2 TxHash,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<(), StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn get_accounts_delta<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            start_version: Option<&'life2 BlockOrTimestamp>,
            end_version: &'life3 BlockOrTimestamp,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<Vec<ContractDelta>, StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: 'async_trait;

    }

    impl ProtocolGateway for Gateway {

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn get_protocol_components<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            system: Option<String>,
            ids: Option<&'life2 [&'life3 str]>,
            min_tvl: Option<f64>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<
                        Vec<ProtocolComponent>,
                        StorageError,
                    >,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn add_protocol_components<'life0, 'life1, 'async_trait>(
            &'life0 self,
            new: &'life1 [ProtocolComponent],
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<(), StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn delete_protocol_components<'life0, 'life1, 'async_trait>(
            &'life0 self,
            to_delete: &'life1 [ProtocolComponent],
            block_ts: NaiveDateTime,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<(), StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn add_protocol_types<'life0, 'life1, 'async_trait>(
            &'life0 self,
            new_protocol_types: &'life1 [ProtocolType],
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<(), StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn get_protocol_states<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            at: Option<Version>,
            system: Option<String>,
            id: Option<&'life2 [&'life3 str]>,
            retrieve_balances: bool,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<
                        Vec<ProtocolComponentState>,
                        StorageError,
                    >,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn update_protocol_states<'life0, 'life1, 'async_trait>(
            &'life0 self,
            new: &'life1 [(TxHash, ProtocolComponentStateDelta)],
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<(), StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn get_tokens<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            chain: Chain,
            address: Option<&'life1 [&'life2 Address]>,
            pagination_params: Option<&'life3 PaginationParams>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<Vec<CurrencyToken>, StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn add_component_balances<'life0, 'life1, 'async_trait>(
            &'life0 self,
            component_balances: &'life1 [ComponentBalance],
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<(), StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn add_tokens<'life0, 'life1, 'async_trait>(
            &'life0 self,
            tokens: &'life1 [CurrencyToken],
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<(), StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn get_protocol_states_delta<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            start_version: Option<&'life2 BlockOrTimestamp>,
            end_version: &'life3 BlockOrTimestamp,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<
                        Vec<ProtocolComponentStateDelta>,
                        StorageError,
                    >,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn get_balance_deltas<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            start_version: Option<&'life2 BlockOrTimestamp>,
            target_version: &'life3 BlockOrTimestamp,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<
                        Vec<ComponentBalance>,
                        StorageError,
                    >,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn get_balances<'life0, 'life1, 'life2, 'life3, 'life4, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            ids: Option<&'life2 [&'life3 str]>,
            at: Option<&'life4 Version>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<HashMap<String, HashMap<Bytes, Bytes>>, StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            'life4: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn get_token_prices<'life0, 'life1, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<HashMap<Bytes, f64>, StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
        fn upsert_component_tvl<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            tvl_values: &'life2 HashMap<String, f64>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<(), StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait;
    }

    impl Gateway for Gateway {}
}

#[cfg(test)]
pub fn evm_contract_slots(data: impl IntoIterator<Item = (i32, i32)>) -> HashMap<Bytes, Bytes> {
    data.into_iter()
        .map(|(s, v)| (Bytes::from(U256::from(s)), Bytes::from(U256::from(v))))
        .collect()
}
