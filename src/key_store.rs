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
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use sodiumoxide::crypto::sign;
use std::collections::{BTreeMap, BTreeSet};

// FIXME: We only work with KeyData and not PublicKey directly
// because PublicKey doesn't derive from Ord in the current version of
// sodiumdioxide library. Once that library is bumped to version 0.0.6
// or above, we should be able to get rid of KeyData and the re-wrapping.
type KeyData   = [u8; sign::PUBLICKEYBYTES];
type Map<A, B> = BTreeMap<A,B>;
type Set<A>    = BTreeSet<A>;

pub struct KeyStore<Name> where Name: Eq + PartialOrd + Ord + Clone {
    quorum_size: usize,
    //            +--- To                  +--- From
    //            V                        V
    key_map: Map<Name, Map<KeyData, Set<Name>>>,
}

impl<Name> KeyStore<Name> where Name: Eq + PartialOrd + Ord + Clone {
    pub fn new(quorum_size: usize) -> KeyStore<Name> {
        KeyStore{ quorum_size: quorum_size
                , key_map: Map::<Name, Map<KeyData, Set<Name>>>::new()
        }
    }

    pub fn add_key(&mut self, to: Name, from: Name, key: sign::PublicKey) {
        let new_map = || { Map::<KeyData, Set<Name>>::new() };
        let new_set = || { Set::<Name>::new() };

        self.key_map.entry(to).or_insert_with(new_map)
                    .entry(key.0).or_insert_with(new_set)
                    .insert(from);
    }

    pub fn get_accumulated_key(&self, to: &Name) -> Option<sign::PublicKey> {
        self.key_map.get(to).and_then(|keys| self.pick_where_quorum_reached(keys))
            .cloned().map(sign::PublicKey)
    }

    fn pick_where_quorum_reached<'a>(&self, keys: &'a Map<KeyData, Set<Name>>) -> Option<&'a KeyData> {
        keys.iter().filter_map(|(key, from_set)| {
            return if from_set.len() >= self.quorum_size { Some(key) } else { None };
        }).nth(0)
    }
}

