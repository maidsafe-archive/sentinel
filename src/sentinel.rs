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

//! Sentinel cryptographically confirms the origin of a claim in a decentralised network.
//!
//! A claim has to implement Claimable in order to be verifiable and mergeable.
//! A request has to implement GetSigningKeys such that Sentinel can aqcuire
//! the necessary public signing keys.
//! The request is passed immutably through sentinel
//! and is used as a key to group claims and corresponding keys.
//! When sentinel resolves a threshold on verified and merged message,
//! it returns the requestor key and the merged claim.
//! Claimant names and associated signatures are discarded after succesful resolution,
//! as such abstracting the original request into a resolved claim.
//!
//! The keys_threshold specifies a minimal threshold on the number of independent mentions of
//! a single public signing key needed to consider it for verifying a claim.  This threshold
//! can be one or higher.
//! The claims_threshold specifies a minimal threshold on the number of verified claims before
//! sentinel will attempt to merge these verified claims.

use super::{SerialisedClaim};

use statistics::Frequency;
use statistics::FrequencyKeyValue;
use std::collections::BTreeMap;

//use sodiumoxide::crypto;
//use sodiumoxide::crypto::sign::verify_detached;
use sodiumoxide::crypto::sign::PublicKey;
use sodiumoxide::crypto::sign::Signature;
// use std::sync::mpsc::channel;
use accumulator::Accumulator;


/// The Request type needs to implement this GetSigningKey trait.
/// Sentinel will call get_signing_keys() the first time it receives a request
/// for which it does not yet have any associated keys.
pub trait GetSigningKeys<Name> where Name: Eq + PartialOrd + Ord  + Clone {
    fn get_signing_keys(&self, source: Name);
}

pub trait Source<Name> where Name: Eq + PartialOrd + Ord  + Clone {
    fn get_source(&self) -> Name;
}

/// Sentinel is templated on an immutable Request type, a mergeable Claim type.
/// It further takes a Name type to identify claimants.
/// Signature and PublicSignKey type are auxiliary types to handle a user-chosen
/// cryptographic signing scheme.
pub struct Sentinel<'a, Request, Name> // later template also on Signature
    where Request: Eq + PartialOrd + Ord + Clone + Source<Name>,
          Name: Eq + PartialOrd + Ord + Clone {
    sender: &'a mut (GetSigningKeys<Name> + 'a),
    claim_accumulator: Accumulator<Request, (Name, Signature, SerialisedClaim)>,
    keys_accumulator: Accumulator<Request, Vec<(Name, PublicKey)>>,
    claim_threshold: usize,
    keys_threshold: usize
}

impl<'a, Request, Name>
    Sentinel<'a, Request, Name>
    where Request: Eq + PartialOrd + Ord + Clone + Source<Name>,
          Name: Eq + PartialOrd + Ord + Clone {
    /// This creates a new sentinel that will collect a minimal claim_threshold number
    /// of verified claims before attempting to merge these claims.
    /// To obtain a verified claim Sentinel needs to have received a matching public
    /// signing key. Each such a public signing key needs keys_threshold confirmations
    /// for it to be considered valid and used for verifying the signature
    /// of the corresponding claim.
    pub fn new(sender: &'a mut GetSigningKeys<Name>, claim_threshold: usize, keys_threshold: usize)
        -> Sentinel<'a, Request, Name> {
        Sentinel {
            sender: sender,
            claim_accumulator: Accumulator::new(claim_threshold),
            keys_accumulator: Accumulator::new(keys_threshold),
            claim_threshold: claim_threshold,
            keys_threshold: keys_threshold
        }
    }

    /// This adds a new claim for the provided request.
    /// The name and the signature provided will be used to validate the claim
    /// with the keys that are independently retrieved.
    /// When an added claim leads to the resolution of the request,
    /// the request and the claim are returned.
    /// All resolved claims have to be identical.
    /// Otherwise None is returned.
    pub fn add_claim(&mut self, request : Request,
                     claimant : Name, signature : Signature,
                     claim : SerialisedClaim)
        // TODO: replace return option with async events pipe to different thread
        // TODO: code can be cleaned up more even by correcting ownership of Accumulator
        -> Option<(Request, SerialisedClaim)> {

        match self.keys_accumulator.get(&request) {
            Some((_, set_of_keys)) => {
                self.claim_accumulator.add(request.clone(), (claimant, signature, claim))
                    .and_then(|(_, claims)| self.validate(&claims, &set_of_keys))
                    .and_then(|verified_claims| self.resolve(&verified_claims))
                    .map(|merged_claim| (request, merged_claim))
            },
            None => {
                self.sender.get_signing_keys(request.get_source());
                self.claim_accumulator.add(request, (claimant, signature, claim));
                return None;
            }
        }
    }

    /// This adds a new set of public_signing_keys for the provided request.
    /// If the request is not known yet by sentinel, the added keys will be ignored.
    /// When the added set of keys leads to the resolution of the request,
    /// the request and the verified and merged claim is returned.
    /// Otherwise None is returned.
    pub fn add_keys(&mut self, request : Request, keys : Vec<(Name, PublicKey)>)
        // return the Request key and only the merged claim
        // TODO: replace return option with async events pipe to different thread
        -> Option<(Request, SerialisedClaim)> {

        match self.claim_accumulator.get(&request) {
            Some((_, claims)) => {
                self.keys_accumulator.add(request.clone(), keys)
                    .and_then(|(_, set_of_keys)| self.validate(&claims, &set_of_keys))
                    .and_then(|verified_claims| self.resolve(&verified_claims))
                    .map(|merged_claim| (request, merged_claim))
            },
            None => {
                // if no corresponding claim exists, refuse to accept keys.
                return None;
            }
        }
    }

    /// Validate is only concerned with checking the signatures of the serialised claims.
    /// To achieve this it pairs up a set of signed claims and a set of public signing keys.
    fn validate(&self, claims : &Vec<(Name, Signature, SerialisedClaim)>,
                       sets_of_keys : &Vec<Vec<(Name, PublicKey)>> ) -> Option<Vec<SerialisedClaim>> {

        let keys = self.flatten_keys(sets_of_keys);

        let verified_claims = claims.iter()
            .filter_map(|claim| {
                keys.get(&claim.0)
                    .and_then(|public_keys| {
                        for public_key in public_keys{
                            match super::check_signature(&claim.1,
                                                         &public_key,
                                                         &claim.2) {
                                Some(claim) => return Some(claim),
                                None => continue
                            }
                        };
                        None
                     })
            })
            .collect::<Vec<SerialisedClaim>>();

        if verified_claims.len() >= self.claim_threshold {
            return Some(verified_claims)
        }

        None
    }

    fn resolve(&self, verified_claims : &Vec<SerialisedClaim>) -> Option<SerialisedClaim> {
        let mut frequency = Frequency::new();
        for verified_claim in verified_claims {
            frequency.update(&verified_claim)
        }

        let resolved_claims = frequency.sort_by_highest().into_iter()
            .filter(|&(_, ref count)| *count >= self.claim_threshold)
            .map(|(resolved_claim, _)| resolved_claim)
            .collect::<Vec<&SerialisedClaim>>();
        assert_eq!(resolved_claims.len(), 1);

        let resolved_claim : Option<SerialisedClaim>
            = match resolved_claims.first() {
            Some(&serialised_claim) => Some(serialised_claim.clone()),
            None => None
        };
        resolved_claim
    }

    fn flatten_keys(&self, sets_of_keys : &Vec<Vec<(Name, PublicKey)>>)
        -> BTreeMap<Name, Vec<PublicKey>> {
        // Key, Value Frequency counts a two-level depth tree of key-values
        // where the occurance of key is the maximum over all value occurances
        // for that key.
        let mut frequency = FrequencyKeyValue::new();

        for keys in sets_of_keys {
            for key in keys {
                // We use raw bytes from the key here because in the current
                // version of sodiumdioxide library PublicKey doesn't derive
                // from Eq nor PartialEq. Once a version greater or equal to
                // 0.0.6 is used, we can get rid of this unwrapping and then
                // rewrapping few lines below.
                frequency.update(&key.0, &(key.1).0);
            }
        }

        // retrieve all name and key combinations with a count,
        // and cut off at threshold.
        // Frequency resolves duplication conflicts internally
        frequency.sort_by_highest().into_iter()
            .filter(|&(_, _, ref count)| *count >= self.keys_threshold)
            .map(|(name, public_keys, _)| {
                (name, public_keys.into_iter()
                                  .filter(|&(_, ref count)| *count >= self.keys_threshold)
                                  .map(|(public_key, _)| PublicKey(public_key))
                                  .collect::<_>())})
            .collect::<BTreeMap<Name, Vec<PublicKey>>>()
    }
}

#[cfg(test)]
mod test {

    extern crate rustc_serialize;
    use super::*;
    //use rustc_serialize::{Decodable, Encodable};

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
    struct TestRequest {
        core : usize
    }

    impl GetSigningKeys<usize> for TestRequest {
        fn get_signing_keys(&self, source: usize) {
            // TODO: can we improve on this now? compared to previous implementation
        }
    }

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
    struct TestClaim {
        value : usize
    }

}
