use std::{collections::HashMap, hash::Hash};

pub trait Shared: Send + Sync + 'static {}

pub struct PartitionedHashMap<K, V> {
    pub matches: HashMap<K, V>,
    pub not_matches: HashMap<K, V>,
}

pub fn partition_hashmap<K, V, P>(hashmap: HashMap<K, V>, predicate: P) -> PartitionedHashMap<K, V>
where
    K: Eq + Hash,
    P: Fn(&K, &V) -> bool,
{
    let mut matches = HashMap::new();
    let mut not_matches = HashMap::new();

    for (k, v) in hashmap {
        if predicate(&k, &v) {
            matches.insert(k, v);
        } else {
            not_matches.insert(k, v);
        }
    }

    PartitionedHashMap {
        matches,
        not_matches,
    }
}
