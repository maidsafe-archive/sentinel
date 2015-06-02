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
use std::fmt::Debug;

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
              Name:    Eq + PartialOrd + Ord + Clone + Debug,
              IdType:  Eq + PartialOrd + Ord + Clone + IdTrait<Name>,
              GroupClaim:  Eq + PartialOrd + Ord + Clone + GroupClaimTrait<IdType> + Debug, {
    cache: LruCache<Request, (KeyStore<Name>, Map<Name, Set<GroupClaim>>)>,
    claim_threshold: usize,
    keys_threshold: usize,
    phantom: PhantomData<IdType>,
}

impl<Request, Name, IdType, GroupClaim> KeySentinel<Request, Name, IdType, GroupClaim>
    where Request: Eq + PartialOrd + Ord + Clone,
          Name:    Eq + PartialOrd + Ord + Clone + Debug,
          IdType:  Eq + PartialOrd + Ord + Clone + IdTrait<Name>,
          GroupClaim: Eq + PartialOrd + Ord + Clone + GroupClaimTrait<IdType> + Debug, {

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

#[cfg(test)]
mod test {
    use super::*;
    use rand::random;
    use sodiumoxide::crypto::sign;
    use std::fmt;

    const MESSAGE_SIZE: usize = 4;
    const CLAIMS_THRESHOLD: usize = 10;
    const KEYS_THRESHOLD: usize = 10;

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
    pub struct TestName(pub u32);

    fn generate_random_message() -> Vec<u8> {
        let mut arr = [0u8;MESSAGE_SIZE];
        for i in (0..MESSAGE_SIZE) { arr[i] = random::<u8>(); }
        arr.to_vec()
    }

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
    struct TestRequest {
        core : usize,
        name : TestName
    }

    impl TestRequest {
        pub fn new(core: usize, name: TestName) -> TestRequest {
            TestRequest { core : core, name : name }
        }
    }

    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct TestIdType {
        name: TestName,
        public_key: [u8;sign::PUBLICKEYBYTES],
    }

    impl IdTrait<TestName> for TestIdType {
        fn name(&self) -> TestName  {
            self.name.clone()
        }

        fn public_key(&self) -> sign::PublicKey {
            sign::PublicKey(self.public_key)
        }
    }

    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct TestGroupClaim {
        serialised_message: Vec<u8>,
        identities: Vec<TestIdType>,
        signature: Vec<u8>,
    }

    impl fmt::Debug for TestGroupClaim {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Message({:?})", self.serialised_message)
        }
    }

    impl TestGroupClaim {
        pub fn new(serialised_message: Vec<u8>,
                   signature: sign::Signature,
                   identities: Vec<TestIdType>) -> TestGroupClaim {

            let mut sig = Vec::<u8>::new();

            for c in signature.0.iter() { sig.push(c.clone()); }

            TestGroupClaim { serialised_message: serialised_message,
                             signature: sig,
                             identities: identities }
        }
    }

    impl GroupClaimTrait<TestIdType> for TestGroupClaim {
        fn group_identities(&self) -> Vec<TestIdType> {
            self.identities.clone()
        }

        fn verify_public_key(&self, public_key: &sign::PublicKey) -> bool {
            let mut sig = [0u8;sign::SIGNATUREBYTES];
            let mut i = 0;
            for byte in &self.signature {
                sig[i] = byte.clone();
                i += 1;
            }
            sign::verify_detached(&sign::Signature(sig), &self.serialised_message, public_key)
        }
    }

#[test]
    fn make_key_sentinel() {
        let mut sentinel: KeySentinel<TestRequest, TestName, TestIdType, TestGroupClaim>
            = KeySentinel::new(CLAIMS_THRESHOLD, KEYS_THRESHOLD);

        let random_message = generate_random_message();

        let mut tuples = Vec::new();
        for i in 0..KEYS_THRESHOLD + 1 {
            let key_pair = sign::gen_keypair();
            let signature = sign::sign_detached(&random_message, &key_pair.1);
            tuples.push((TestName(i as u32), key_pair.0, signature));
        }

        let request = TestRequest::new(random::<usize>(), TestName((KEYS_THRESHOLD+1) as u32));

        let name_pubs = tuples.iter().map(|&(ref name, ref public_key, _)|
                                            TestIdType { name: name.clone(),
                                                         public_key: public_key.clone().0 })
                                     .collect::<Vec<_>>();

        for index in 0..KEYS_THRESHOLD + 1 {
            let group_claim = TestGroupClaim::new(random_message.clone(),
                                                  tuples[index].2.clone(),
                                                  name_pubs.clone());
            if index < KEYS_THRESHOLD {
                assert!(sentinel.add_identities(request.clone(),
                                                tuples[index].0.clone(),
                                                group_claim).is_none());
                continue;
            }
            assert!(sentinel.add_identities(request.clone(),
                                            tuples[KEYS_THRESHOLD].0.clone(),
                                            group_claim).is_some());
        }
    }
}
