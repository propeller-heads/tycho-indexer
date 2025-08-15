//! Asset inventory system for storing assets between chain steps.

use std::{collections::HashMap, fmt};

use crate::{
    action::asset::{Asset, AssetError},
    Bytes,
};

/// Storage for assets that can be accessed between chain steps.
///
/// The inventory uses type-erased asset storage to handle different asset types
/// uniformly. Assets are indexed by their kind and type identifier. Multiple assets
/// of the same type are automatically accumulated using the Asset::accumulate method.
#[derive(Default)]
pub struct AssetInventory {
    /// Type-erased assets stored by composite key: "kind:type_id_hex"
    assets: HashMap<String, Box<dyn Asset>>,
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
    ///
    /// If an asset of the same type already exists, it will be accumulated with the new asset.
    /// Returns an error if the assets cannot be accumulated (incompatible types).
    pub fn store(&mut self, asset: Box<dyn Asset>) -> Result<(), AssetError> {
        let key = self.storage_key(asset.as_ref());
        if let Some(existing_asset) = self.assets.remove(&key) {
            // Accumulate with existing asset
            let accumulated = existing_asset.accumulate(asset.as_ref())?;
            self.assets.insert(key, accumulated);
        } else {
            // No existing asset, store directly
            self.assets.insert(key, asset);
        }
        Ok(())
    }

    /// Retrieve and remove an asset from the inventory.
    pub fn retrieve(&mut self, kind: &str, type_id: &Bytes) -> Option<Box<dyn Asset>> {
        let key = format!("{}:{}", kind, hex::encode(type_id));
        self.assets.remove(&key)
    }

    /// Get a reference to an asset without removing it from the inventory.
    pub fn get(&self, kind: &str, type_id: &Bytes) -> Option<&Box<dyn Asset>> {
        let key = format!("{}:{}", kind, hex::encode(type_id));
        self.assets.get(&key)
    }

    /// Clear all assets from the inventory.
    pub fn clear(&mut self) {
        self.assets.clear();
    }
}

impl fmt::Debug for AssetInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssetInventory")
            .field("asset_count", &self.assets.len())
            .finish()
    }
}
