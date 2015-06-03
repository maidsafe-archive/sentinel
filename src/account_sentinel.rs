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

type Map<K,V> = BTreeMap<K,V>;
type Set<V>   = BTreeSet<V>;

#[allow(dead_code)]
const MAX_REQUEST_COUNT: usize = 1000;

#[allow(dead_code)]
pub struct AccountSentinel<Request, Name, Claim>
    where Request: Eq + PartialOrd + Ord + Clone,
          Name:    Eq + PartialOrd + Ord + Clone,
          Claim:   Eq + PartialOrd + Ord + Clone, {

    requests: LruCache<Request, Map<Name, Claim>>,
}

impl<Request, Name, Claim> AccountSentinel<Request, Name, Claim>
    where Request: Eq + PartialOrd + Ord + Clone,
          Name:    Eq + PartialOrd + Ord + Clone,
          Claim:   Eq + PartialOrd + Ord + Clone, {

    #[allow(dead_code)]
    pub fn new() -> AccountSentinel<Request, Name, Claim> {
        AccountSentinel {
            requests: LruCache::with_capacity(MAX_REQUEST_COUNT),
        }
    }

    #[allow(dead_code)]
    pub fn add_claim(&mut self, threshold: usize, request: Request, sender: Name, claim: Claim)
        -> Option<Claim> {
        {
            let map = self.requests.entry(request.clone()).or_insert_with(||Map::new());
            map.insert(sender, claim);
            if map.len() < threshold {
                return None;
            }
            Self::pick_median(map).map(|claim|(request, claim))
        }.map(|(request, claim)| {
            self.requests.remove(&request);
            claim
        })
    }

    fn pick_median(map: &Map<Name, Claim>) -> Option<Claim> {
        if map.is_empty() { return None }
        let mut claims = map.iter().map(|(_, ref claim)| claim.clone())
                            .collect::<Vec<_>>();
        claims.sort();
        Some(claims[claims.len() / 2].clone())
    }
}
