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
use sodiumoxide::crypto::sign;
use std::collections::{BTreeSet, BTreeMap};
use key_store::KeyStore;
use std::marker::PhantomData;

#[allow(dead_code)]
const MAX_REQUEST_COUNT: usize = 1000;

type Map<K,V> = BTreeMap<K,V>;
type Set<V>   = BTreeSet<V>;

pub trait IdTrait<NameType> {
    fn name(&self) -> NameType;
    fn public_key(&self) -> sign::PublicKey;
}

pub trait GroupClaimTrait<IdTrait> {
    fn group_identities(&self) -> Vec<IdTrait>;
    fn verify_public_key(&self, _: &sign::PublicKey) -> bool;
}

#[allow(dead_code)]
pub struct KeySentinel<Request, Name, IdType, GroupClaim>
        where Request: Eq + PartialOrd + Ord + Clone,
              Name:    Eq + PartialOrd + Ord + Clone,
              IdType:  Eq + PartialOrd + Ord + Clone + IdTrait<Name>,
              GroupClaim:  Eq + PartialOrd + Ord + Clone + GroupClaimTrait<IdType>, {
    cache: LruCache<Request, (KeyStore<Name>, Map<Name, Set<GroupClaim>>)>,
    claim_threshold: usize,
    keys_threshold: usize,
    phantom: PhantomData<IdType>,
}

impl<Request, Name, IdType, GroupClaim> KeySentinel<Request, Name, IdType, GroupClaim>
    where Request: Eq + PartialOrd + Ord + Clone,
          Name:    Eq + PartialOrd + Ord + Clone,
          IdType:  Eq + PartialOrd + Ord + Clone + IdTrait<Name>,
          GroupClaim: Eq + PartialOrd + Ord + Clone + GroupClaimTrait<IdType>, {

    #[allow(dead_code)]
    pub fn new(claim_threshold: usize, keys_threshold: usize)
            -> KeySentinel<Request, Name, IdType, GroupClaim> {
        KeySentinel {
            cache: LruCache::with_capacity(MAX_REQUEST_COUNT),
            claim_threshold: claim_threshold,
            keys_threshold: keys_threshold,
            phantom: PhantomData,
        }
    }

    #[allow(dead_code)]
    pub fn add_identities(&mut self,
                          request : Request,
                          sender  : Name,
                          claim   : GroupClaim)
        -> Option<(Request, Vec<IdType>)> {

        let retval = {
            let keys_threshold = self.keys_threshold;
            let keys_and_claims
                = self.cache.entry(request.clone())
                            .or_insert_with(||(KeyStore::new(keys_threshold), Map::new()));

            let ref mut keys   = &mut keys_and_claims.0;
            let ref mut claims = &mut keys_and_claims.1;

            for id in claim.group_identities() {
                keys.add_key(id.name(), sender.clone(), id.public_key());
            }

            claims.entry(sender).or_insert_with(||Set::new()).insert(claim);

            Self::try_selecting_group(keys, claims, self.claim_threshold)
                .map(|ids|(request, ids))
        };

        retval.map(|(request, ids)| {
            self.cache.remove(&request);
            (request, ids)
        })
    }

    fn try_selecting_group(key_store: &mut KeyStore<Name>,
                           claims: &Map<Name, Set<GroupClaim>>,
                           claim_threshold: usize) -> Option<Vec<IdType>> {

        let verified_claims = claims.iter().filter_map(|(name, claims)| {
            for claim in claims {
                if Self::verify_claim(name, key_store, claim) {
                    return Some(claim);
                }
            }
            None
        }).collect::<Set<_>>();

        if verified_claims.len() < claim_threshold {
            return None;
        }

        Some(verified_claims.iter().flat_map(|claim| claim.group_identities()).collect())
    }

    fn verify_claim(author: &Name, key_store: &mut KeyStore<Name>, claim: &GroupClaim) -> bool {
        for public_key in key_store.get_accumulated_keys(&author) {
            if claim.verify_public_key(&public_key) {
                return true
            }
        }
        false
    }
}

