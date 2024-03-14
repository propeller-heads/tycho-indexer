//! Contains a mock store for internal testing.
//!
//! Might make this public alter to users can test their store handlers.
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use substreams::prelude::{BigInt, StoreDelete, StoreGet, StoreNew};
use substreams::store::StoreAdd;

type BigIntStore = HashMap<String, Vec<(u64, BigInt)>>;

#[derive(Debug, Clone)]
pub struct MockStore {
    data: Rc<RefCell<BigIntStore>>,
}

impl StoreDelete for MockStore {
    fn delete_prefix(&self, _ord: i64, prefix: &String) {
        self.data
            .borrow_mut()
            .retain(|k, _| !k.starts_with(prefix));
    }
}

impl StoreNew for MockStore {
    fn new() -> Self {
        Self { data: Rc::new(RefCell::new(HashMap::new())) }
    }
}

impl StoreAdd<BigInt> for MockStore {
    fn add<K: AsRef<str>>(&self, ord: u64, key: K, value: BigInt) {
        let mut guard = self.data.borrow_mut();
        guard
            .entry(key.as_ref().to_string())
            .and_modify(|v| {
                let prev_value = v.last().unwrap().1.clone();
                v.push((ord, prev_value + value.clone()));
            })
            .or_insert(vec![(ord, value)]);
    }

    fn add_many<K: AsRef<str>>(&self, _ord: u64, _keys: &Vec<K>, _value: BigInt) {
        todo!()
    }
}

impl StoreGet<BigInt> for MockStore {
    fn new(_idx: u32) -> Self {
        Self { data: Rc::new(RefCell::new(HashMap::new())) }
    }

    fn get_at<K: AsRef<str>>(&self, ord: u64, key: K) -> Option<BigInt> {
        self.data
            .borrow()
            .get(&key.as_ref().to_string())
            .map(|v| {
                v.iter()
                    .find(|(current_ord, _)| *current_ord == ord)
                    .unwrap()
                    .1
                    .clone()
            })
    }

    fn get_last<K: AsRef<str>>(&self, key: K) -> Option<BigInt> {
        self.data
            .borrow()
            .get(&key.as_ref().to_string())
            .map(|v| v.last().unwrap().1.clone())
    }

    fn get_first<K: AsRef<str>>(&self, key: K) -> Option<BigInt> {
        self.data
            .borrow()
            .get(&key.as_ref().to_string())
            .map(|v| v.first().unwrap().1.clone())
    }

    fn has_at<K: AsRef<str>>(&self, ord: u64, key: K) -> bool {
        self.data
            .borrow()
            .get(&key.as_ref().to_string())
            .map(|v| v.iter().any(|(v, _)| *v == ord))
            .unwrap_or(false)
    }

    fn has_last<K: AsRef<str>>(&self, _key: K) -> bool {
        todo!()
    }

    fn has_first<K: AsRef<str>>(&self, _key: K) -> bool {
        todo!()
    }
}
