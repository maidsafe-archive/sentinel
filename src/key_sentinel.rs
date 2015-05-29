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

use lru_time_cache::LruCache;
use std::collections::{BTreeSet, BTreeMap};

const MAX_REQUEST_COUNT: usize = 1000;

type Map<K,V> = BTreeMap<K,V>;
type Set<V>   = BTreeSet<V>;

pub struct KeySentinel<Request, Name, IdType>
        where Request: Eq + PartialOrd + Ord + Clone,
              Name:    Eq + PartialOrd + Ord + Clone,
              IdType:  Eq + PartialOrd + Ord + Clone, {
    cache: LruCache<Request, Map<IdType, Set<Name>>>,
    claim_threshold: usize,
    keys_threshold: usize,
}

impl<Request, Name, IdType> KeySentinel<Request, Name, IdType>
    where Request: Eq + PartialOrd + Ord + Clone,
          Name:    Eq + PartialOrd + Ord + Clone,
          IdType:  Eq + PartialOrd + Ord + Clone, {

    pub fn new(claim_threshold: usize, keys_threshold: usize)
            -> KeySentinel<Request, Name, IdType> {
        KeySentinel {
            cache: LruCache::with_capacity(MAX_REQUEST_COUNT),
            claim_threshold: claim_threshold,
            keys_threshold: keys_threshold,
        }
    }

    pub fn add_identities(&mut self,
                          request    : Request,
                          sender     : Name,
                          identities : Vec<IdType>)
        -> Option<(Request, Vec<IdType>)> {

        let mut ids = self.cache.entry(request.clone()).or_insert_with(||Map::new());

        for id in identities {
            ids.entry(id).or_insert_with(||Set::new()).insert(sender.clone());
        }

        Self::try_selecting_group(&ids, self.claim_threshold, self.keys_threshold)
            .map(|ids| {
                (request, ids)
            })
    }

    fn try_selecting_group(ids: &Map<IdType, Set<Name>>,
                           claim_threshold: usize,
                           keys_threshold: usize) -> Option<Vec<IdType>> {
        let mut confirmed_ids = ids.iter()
                               .map(|(id, senders)| (id, senders.len()))
                               .filter(|&(_, ref cnt)| *cnt >= keys_threshold)
                               .collect::<Vec<_>>();

        if confirmed_ids.len() < claim_threshold {
            return None;
        }

        confirmed_ids.sort_by(|a, b| b.1.cmp(&a.1));
        Some(confirmed_ids.iter().map(|pair|pair.0.clone()).collect())
    }
}

