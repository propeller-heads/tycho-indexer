//! Asset inventory system for storing assets between chain steps.

use std::{collections::HashMap, fmt};

use crate::{action::asset::Asset, Bytes};

/// Storage for assets that can be accessed between chain steps.
///
/// The inventory uses type-erased asset storage to handle different asset types
/// uniformly. Assets are indexed by their kind and type identifier for efficient
/// retrieval and management.
#[derive(Default)]
pub struct AssetInventory {
    /// Type-erased assets stored by composite key: "kind:type_id_hex"
    assets: HashMap<String, Vec<Box<dyn Asset>>>,
}

impl AssetInventory {
    /// Create a new empty asset inventory.
    pub fn new() -> Self {
        Self { assets: HashMap::new() }
    }

    /// Generate a storage key for the given asset.
    fn storage_key(&self, asset: &dyn Asset) -> String {
        format!("{}:{}", asset.kind(), hex::encode(asset.type_id()))
    }

    /// Store an asset in the inventory.
    pub fn push(&mut self, asset: Box<dyn Asset>) {
        let key = self.storage_key(asset.as_ref());
        self.assets
            .entry(key)
            .or_default()
            .push(asset);
    }

    /// Retrieve the most recently stored asset of the given type.
    pub fn pop(&mut self, kind: &str, type_id: &Bytes) -> Option<Box<dyn Asset>> {
        let key = format!("{}:{}", kind, hex::encode(type_id));
        self.assets.get_mut(&key)?.pop()
    }

    /// Clear all assets from the inventory.
    pub fn clear(&mut self) {
        self.assets.clear();
    }
}

impl fmt::Debug for AssetInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssetInventory")
            .field("asset_type_count", &self.assets.len())
            .field(
                "total_asset_count",
                &self
                    .assets
                    .values()
                    .map(|assets| assets.len())
                    .sum::<usize>(),
            )
            .finish()
    }
}
