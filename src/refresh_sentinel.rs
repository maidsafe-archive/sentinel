// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.

extern crate lru_time_cache;
use lru_time_cache::LruCache;

/// Entry for accumulation.
#[derive(Clone)]
pub struct Entry<V> {
    /// Values accumulated for a given key.
    pub received_response: Vec<V>,
}

/// Generic type for accumulating multiple values under a given key.
#[allow(dead_code)]
pub struct RefreshSentinel<K, V>
    where K: PartialOrd + Ord + Clone,
          V: Clone
{
    /// Threshold for resolution.
    quorum: usize,
    storage: LruCache<K, Entry<V>>,
}

impl<K: PartialOrd + Ord + Clone, V: Clone> RefreshSentinel<K, V> {
    /// Construct with quorum.
    #[allow(dead_code)]
    pub fn new(quorum: usize) -> RefreshSentinel<K, V> {
        RefreshSentinel { quorum: quorum, storage: LruCache::<K, Entry<V>>::with_capacity(1000) }
    }

    /// Check for the existence of a key.
    #[allow(dead_code)]
    pub fn contains_key(&self, key: &K) -> bool {
        self.storage.check(key)
    }

    /// Check whether a quorum of values has been accumulated for the given key.
    #[allow(dead_code)]
    pub fn is_quorum_reached(&mut self, key: &K) -> bool {
        let entry = self.storage.get(key);

        if entry.is_none() {
            false
        } else {
            entry.unwrap().received_response.len() >= self.quorum
        }
    }

    /// Adds a key/value pair, if the key already exists add the value under that key.
    /// Optionally returns the key and the vector of values if the quroum has been reached.
    #[allow(dead_code)]
    pub fn add(&mut self, key: K, value: V) -> Option<(K, Vec<V>)> {
        let entry = self.storage.remove(&key);
        if entry.is_none() {
            let entry_in = Entry { received_response: vec![value] };
            self.storage.add(key.clone(), entry_in.clone());
            if self.quorum == 1 {
                let result = (key, entry_in.received_response);
                return Some(result);
            }
        } else {
            let mut tmp = entry.unwrap();
            tmp.received_response.push(value);
            self.storage.add(key.clone(), tmp.clone());
            if tmp.received_response.len() >= self.quorum {
                return Some((key, tmp.received_response));
            }
        }
        None
    }

    /// Retrieve a key/vec<value> pair from the cache.
    #[allow(dead_code)]
    pub fn get(&mut self, key: &K) -> Option<(K, Vec<V>)> {
        let entry = self.storage.get(key);
        if entry.is_none() {
            None
        } else {
            Some((key.clone(), entry.unwrap().received_response.clone()))
        }
    }

    /// Remove all values for the given key.
    #[allow(dead_code)]
    pub fn delete(&mut self, key: &K) {
        self.storage.remove(key);
    }

    /// Return the size of the cache.
    #[allow(dead_code)]
    pub fn cache_size(&mut self) -> usize {
        self.storage.len()
    }

    /// Set the quorum to a new value.
    #[allow(dead_code)]
    pub fn set_quorum(&mut self, quorum: usize) {
        self.quorum = quorum;
    }
}

#[cfg(test)]
mod test {
    extern crate rand;
    use super::*;

    #[test]
    fn add() {
        let mut sentinel: RefreshSentinel<i32, u32> = RefreshSentinel::new(1);

        assert!(sentinel.add(2, 3).is_some());
        assert_eq!(sentinel.contains_key(&1), false);
        assert_eq!(sentinel.contains_key(&2), true);
        assert_eq!(sentinel.is_quorum_reached(&1), false);
        assert_eq!(sentinel.is_quorum_reached(&2), true);
        assert!(sentinel.add(1, 3).is_some());
        assert_eq!(sentinel.contains_key(&1), true);
        assert_eq!(sentinel.is_quorum_reached(&1), true);
        assert!(sentinel.add(1, 3).is_some());
        assert_eq!(sentinel.contains_key(&1), true);
        assert_eq!(sentinel.is_quorum_reached(&1), true);

        let (key, responses) = sentinel.get(&1).unwrap();

        assert_eq!(key, 1);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0], 3);
        assert_eq!(responses[1], 3);

        let (key, responses) = sentinel.get(&2).unwrap();

        assert_eq!(key, 2);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0], 3);
    }

    #[test]
    fn add_single_value_quorum() {
        let quorum_size: usize = 19;
        let mut sentinel: RefreshSentinel<i32, u32> = RefreshSentinel::new(quorum_size);
        let key = rand::random::<i32>();
        let value = rand::random::<u32>();
        for i in 0..quorum_size - 1 {
            assert!(sentinel.add(key, value).is_none());
            let key_value = sentinel.get(&key).unwrap();
            assert_eq!(key_value.0, key);
            assert_eq!(key_value.1.len(), i + 1);
            for response in key_value.1 {
                assert_eq!(response, value);
            };
            assert_eq!(sentinel.is_quorum_reached(&key), false);
        }
        assert!(sentinel.add(key, value).is_some());
        assert_eq!(sentinel.is_quorum_reached(&key), true);
        let key_value = sentinel.get(&key).unwrap();
        assert_eq!(key_value.0, key);
        assert_eq!(key_value.1.len(), quorum_size);
        for response in key_value.1 {
            assert_eq!(response, value);
        };
    }

    #[test]
    fn add_multiple_values_quorum() {
        let quorum_size: usize = 19;
        let mut sentinel: RefreshSentinel<i32, u32> = RefreshSentinel::new(quorum_size);
        let key = rand::random::<i32>();
        for _ in 0..quorum_size - 1 {
            assert!(sentinel.add(key, rand::random::<u32>()).is_none());
            assert_eq!(sentinel.is_quorum_reached(&key), false);
        }
        assert!(sentinel.add(key, rand::random::<u32>()).is_some());
        assert_eq!(sentinel.is_quorum_reached(&key), true);
    }

    #[test]
    fn add_multiple_keys_quorum() {
        let quorum_size: usize = 19;
        let mut sentinel: RefreshSentinel<i32, u32> = RefreshSentinel::new(quorum_size);
        let key = rand::random::<i32>();
        let mut noise_keys: Vec<i32> = Vec::with_capacity(5);
        while noise_keys.len() < 5 {
            let noise_key = rand::random::<i32>();
            if noise_key != key {
                noise_keys.push(noise_key);
            };
        };
        for _ in 0..quorum_size - 1 {
            for noise_key in noise_keys.iter() {
                sentinel.add(noise_key.clone(), rand::random::<u32>());
            }
            assert!(sentinel.add(key, rand::random::<u32>()).is_none());
            assert_eq!(sentinel.is_quorum_reached(&key), false);
        }
        assert!(sentinel.add(key, rand::random::<u32>()).is_some());
        assert_eq!(sentinel.is_quorum_reached(&key), true);
    }

    #[test]
    fn delete() {
        let mut sentinel: RefreshSentinel<i32, u32> = RefreshSentinel::new(2);

        assert!(sentinel.add(1, 1).is_none());
        assert_eq!(sentinel.contains_key(&1), true);
        assert_eq!(sentinel.is_quorum_reached(&1), false);

        let (key, responses) = sentinel.get(&1).unwrap();

        assert_eq!(key, 1);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0], 1);

        sentinel.delete(&1);

        let option = sentinel.get(&1);

        assert!(option.is_none());

        assert!(sentinel.add(1, 1).is_none());
        assert_eq!(sentinel.contains_key(&1), true);
        assert_eq!(sentinel.is_quorum_reached(&1), false);
        assert!(sentinel.add(1, 1).is_some());
        assert_eq!(sentinel.contains_key(&1), true);
        assert_eq!(sentinel.is_quorum_reached(&1), true);

        let (key, responses) = sentinel.get(&1).unwrap();

        assert_eq!(key, 1);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0], 1);
        assert_eq!(responses[1], 1);

        sentinel.delete(&1);

        let option = sentinel.get(&1);

        assert!(option.is_none());
    }

    #[test]
    fn fill() {
        let mut sentinel: RefreshSentinel<i32, u32> = RefreshSentinel::new(1);

        for count in 0..1000 {
            assert!(sentinel.add(count, 1).is_some());
            assert_eq!(sentinel.contains_key(&count), true);
            assert_eq!(sentinel.is_quorum_reached(&count), true);
        }

        for count in 0..1000 {
            let (key, responses) = sentinel.get(&count).unwrap();

            assert_eq!(key, count);
            assert_eq!(responses.len(), 1);
            assert_eq!(responses[0], 1);
        }
    }

    #[test]
    fn cache_removals() {
        let mut sentinel: RefreshSentinel<i32, u32> = RefreshSentinel::new(2);

        for count in 0..1000 {
            assert!(sentinel.add(count, 1).is_none());
            assert_eq!(sentinel.contains_key(&count), true);
            assert_eq!(sentinel.is_quorum_reached(&count), false);

            let (key, responses) = sentinel.get(&count).unwrap();

            assert_eq!(key, count);
            assert_eq!(responses.len(), 1);
            assert_eq!(responses[0], 1);
            assert_eq!(sentinel.cache_size(), count as usize + 1);
        }

        assert!(sentinel.add(1000, 1).is_none());
        assert_eq!(sentinel.contains_key(&1000), true);
        assert_eq!(sentinel.is_quorum_reached(&1000), false);
        assert_eq!(sentinel.cache_size(), 1000);

        for count in 0..1000 {
            let option = sentinel.get(&count);

            assert!(option.is_none());

            assert!(sentinel.add(count + 1001, 1).is_none());
            assert_eq!(sentinel.contains_key(&(count + 1001)), true);
            assert_eq!(sentinel.is_quorum_reached(&(count + 1001)), false);
            assert_eq!(sentinel.cache_size(), 1000);
        }
    }

    #[test]
    fn set_quorum_size() {
        let mut sentinel: RefreshSentinel<i32, u32> = RefreshSentinel::new(2);
        let random = rand::random::<usize>();
        sentinel.set_quorum(random);
        assert_eq!(random, sentinel.quorum);
    }
}
