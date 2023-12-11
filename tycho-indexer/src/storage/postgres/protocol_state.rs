use async_trait::async_trait;

use crate::{
    models::{Chain, ProtocolComponent, ProtocolState, ProtocolSystem},
    storage::{
        postgres::{orm, PostgresGateway},
        Address, BlockIdentifier, BlockOrTimestamp, ContractDelta, ProtocolStateGateway,
        StorableBlock, StorableContract, StorableTransaction, StorageError, TxHash, Version,
    },
};

#[async_trait]
impl<B, TX, A, D> ProtocolStateGateway for PostgresGateway<B, TX, A, D>
where
    B: StorableBlock<orm::Block, orm::NewBlock, i64>,
    TX: StorableTransaction<orm::Transaction, orm::NewTransaction, i64>,
    D: ContractDelta + From<A>,
    A: StorableContract<orm::Contract, orm::NewContract, i64>,
{
    type DB = ();
    type Token = ();
    type ProtocolState = ();

    async fn get_components(
        &self,
        chain: &Chain,
        system: Option<ProtocolSystem>,
        ids: Option<&[&str]>,
    ) -> Result<Vec<ProtocolComponent<Self::Token>>, StorageError> {
        todo!()
    }

    async fn upsert_components(
        &self,
        new: &[&ProtocolComponent<Self::Token>],
    ) -> Result<(), StorageError> {
        todo!()
    }

    async fn get_states(
        &self,
        chain: Chain,
        at: Option<Version>,
        system: Option<ProtocolSystem>,
        id: Option<&[&str]>,
    ) -> Result<Vec<ProtocolState>, StorageError> {
        todo!()
    }

    async fn update_state(&self, chain: Chain, new: &[(TxHash, ProtocolState)], db: &mut Self::DB) {
        todo!()
    }

    async fn get_tokens(
        &self,
        chain: Chain,
        address: Option<&[&Address]>,
    ) -> Result<Vec<Self::Token>, StorageError> {
        todo!()
    }

    async fn add_tokens(&self, chain: Chain, token: &[&Self::Token]) -> Result<(), StorageError> {
        todo!()
    }

    async fn get_state_delta(
        &self,
        chain: &Chain,
        system: Option<ProtocolSystem>,
        id: Option<&[&str]>,
        start_version: Option<&BlockOrTimestamp>,
        end_version: &BlockOrTimestamp,
    ) -> Result<ProtocolState, StorageError> {
        todo!()
    }

    async fn revert_protocol_state(&self, to: &BlockIdentifier) -> Result<(), StorageError> {
        todo!()
    }
}
