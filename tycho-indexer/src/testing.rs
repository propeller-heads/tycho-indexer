use std::collections::HashMap;
#[cfg(test)]
use std::time::Duration;

use async_trait::async_trait;
use chrono::NaiveDateTime;
use mockall::mock;

use tycho_core::{
    models::{
        blockchain::{Block, Transaction},
        contract::{Account, AccountBalance, AccountDelta},
        protocol::{
            ComponentBalance, ProtocolComponent, ProtocolComponentState,
            ProtocolComponentStateDelta,
        },
        token::CurrencyToken,
        Address, Chain, ComponentId, ContractId, ExtractionState, PaginationParams, ProtocolType,
        TxHash,
    },
    storage::{
        BlockIdentifier, BlockOrTimestamp, ChainGateway, ContractStateGateway,
        ExtractionStateGateway, Gateway, ProtocolGateway, StorageError, Version, WithTotal,
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
        fn get_contract<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            id: &'life1 ContractId,
            version: Option<&'life2 Version>,
            include_slots: bool,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<Account, StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity)]
        fn get_contracts<'life0, 'life1, 'life2, 'life3, 'life4, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            addresses: Option<&'life2 [Address]>,
            version: Option<&'life3 Version>,
            include_slots: bool,
            pagination_params: Option<&'life4 PaginationParams>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<WithTotal<Vec<Account>>, StorageError>,
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

        fn upsert_contract<'life0, 'life1, 'async_trait>(
            &'life0 self,
            new: &'life1 Account,
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

        fn update_contracts<'life0, 'life1, 'async_trait>(
            &'life0 self,
            new: &'life1 [(TxHash, AccountDelta)],
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

        fn get_accounts_delta<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            start_version: Option<&'life2 BlockOrTimestamp>,
            end_version: &'life3 BlockOrTimestamp,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<Vec<AccountDelta>, StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: 'async_trait;


        fn add_account_balances<'life0, 'life1, 'async_trait>(
            &'life0 self,
            account_balances: &'life1 [AccountBalance],
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

        #[allow(clippy::type_complexity)]
        fn get_account_balances<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            accounts: Option<&'life2 [Address]>,
            version: Option<&'life3 Version>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<HashMap<Address, HashMap<Address, AccountBalance>>, StorageError>,
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
        #[allow(clippy::type_complexity)]
        fn get_protocol_components<'life0, 'life1, 'life2, 'life3, 'life4, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            system: Option<String>,
            ids: Option<&'life2 [&'life3 str]>,
            min_tvl: Option<f64>,
            pagination_params: Option<&'life4 PaginationParams>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<WithTotal<Vec<ProtocolComponent>>,
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
            'life4: 'async_trait,
            Self: 'async_trait;

        #[allow(clippy::type_complexity)]
        fn get_token_owners<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            tokens: &'life2 [Address],
            min_balance: Option<f64>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<
                        HashMap<Address, (ComponentId, Bytes)>,
                        StorageError,
                    >,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait;

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

        #[allow(clippy::type_complexity)]
        fn get_protocol_states<'life0, 'life1, 'life2, 'life3, 'life4, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            at: Option<Version>,
            system: Option<String>,
            ids: Option<&'life2 [&'life3 str]>,
            retrieve_balances: bool,
            pagination_params: Option<&'life4 PaginationParams>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<WithTotal<Vec<ProtocolComponentState>>,
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
            'life4: 'async_trait,
            Self: 'async_trait;

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

        #[allow(clippy::type_complexity)]
        fn get_tokens<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            chain: Chain,
            address: Option<&'life1 [&'life2 Address]>,
            min_quality: Option<i32>,
            traded_n_days_ago: Option<NaiveDateTime>,
            pagination_params: Option<&'life3 PaginationParams>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<WithTotal<Vec<CurrencyToken>>, StorageError>,
                > + ::core::marker::Send + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: 'async_trait;

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

        fn update_tokens<'life0, 'life1, 'async_trait>(
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

        #[allow(clippy::type_complexity)]
        fn get_component_balances<'life0, 'life1, 'life2, 'life3, 'life4, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            ids: Option<&'life2 [&'life3 str]>,
            version: Option<&'life4 Version>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<HashMap<String, HashMap<Bytes, ComponentBalance>>, StorageError>,
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

        #[allow(clippy::type_complexity)]
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

        #[allow(clippy::type_complexity)]
        fn get_protocol_systems<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            chain: &'life1 Chain,
            pagination_params: Option<&'life2 PaginationParams>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                    Output = Result<WithTotal<Vec<String>>, StorageError>,
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
        .map(|(s, v)| {
            (Bytes::from(u32::try_from(s).unwrap()), Bytes::from(u32::try_from(v).unwrap()))
        })
        .collect()
}

/// Creates a block for testing, version 0 is not allowed and will panic.
#[cfg(test)]
pub fn block(version: u64) -> Block {
    if version == 0 {
        panic!("Block version 0 doesn't exist. Smallest version is 1");
    }

    let ts: NaiveDateTime = "2020-01-01T00:00:00"
        .parse()
        .expect("failed parsing block ts");
    Block::new(
        version,
        Chain::Ethereum,
        Bytes::from(version).lpad(32, 0),
        Bytes::from(version - 1).lpad(32, 0),
        ts + Duration::from_secs(version * 12),
    )
}
