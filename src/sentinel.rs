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

use sodiumoxide::crypto::sign::PublicKey;
use sodiumoxide::crypto::sign::Signature;
use accumulator::Accumulator;
use key_store::KeyStore;

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
pub struct Sentinel<'a, Request, Name>

    where Request: Eq + PartialOrd + Ord + Clone + Source<Name>,
          Name: Eq + PartialOrd + Ord + Clone {
    sender: &'a mut (GetSigningKeys<Name> + 'a),
    claim_accumulator: Accumulator<Request, (Name, Signature, SerialisedClaim)>,
    key_store: KeyStore<Name>,
    claim_threshold: usize,
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
            key_store: KeyStore::<Name>::new(keys_threshold),
            claim_threshold: claim_threshold,
        }
    }

    /// This adds a new claim for the provided request.
    /// The name and the signature provided will be used to verify the claim
    /// with the keys that are independently retrieved.
    /// When an added claim leads to the resolution of the request,
    /// the request and the claim are returned.
    /// All resolved claims have to be identical.
    /// Otherwise None is returned.
    pub fn add_claim(&mut self,
                     request   : Request,
                     claimant  : Name,            // Node which sent the message
                     signature : Signature,
                     claim     : SerialisedClaim)
        -> Option<(Request, SerialisedClaim)> {

        let saw_first_time = !self.claim_accumulator.contains_key(&request);

        let retval = self.claim_accumulator.add(request.clone(), (claimant, signature, claim))
            .and_then(|(request, claims)| self.resolve(request, claims));

        if saw_first_time && retval.is_none() {
            self.sender.get_signing_keys(request.get_source());
        }

        retval
    }

    /// This adds a new set of public_signing_keys for the provided request.
    /// If the request is not known yet by sentinel, the added keys will be ignored.
    /// When the added set of keys leads to the resolution of the request,
    /// the request and the verified and merged claim is returned.
    /// Otherwise None is returned.
    pub fn add_keys(&mut self, request : Request, keys : Vec<(Name, PublicKey)>)
        -> Option<(Request, SerialisedClaim)> {
        self.claim_accumulator.get(&request)
            .and_then(|(request, claims)| {
                for (target, public_key) in keys {
                    self.key_store.add_key(target, request.get_source(), public_key);
                }

                self.resolve(request, claims)
            })
    }

    /// Verify is only concerned with checking the signatures of the serialised claims.
    /// To achieve this it pairs up a set of signed claims and a set of public signing keys.
    fn verify(&mut self, claims : &Vec<(Name, Signature, SerialisedClaim)>)
        -> Vec<SerialisedClaim> {
        claims.iter().filter_map(|&(ref name, ref signature, ref body)| {
                self.verify_single_claim(name, signature, body)
            }).collect()
    }

    fn verify_single_claim(&mut self, name: &Name, signature: &Signature, body: &SerialisedClaim)
        -> Option<SerialisedClaim> {
        for public_key in self.key_store.get_accumulated_keys(&name) {
            match super::verify_signature(&signature, &public_key, &body) {
                Some(body) => return Some(body),
                None => continue
            }
        }
        None
    }

    fn squash(&self, verified_claims : Vec<SerialisedClaim>) -> Option<SerialisedClaim> {
        if verified_claims.len() <= self.claim_threshold {
            // Can't squash: not enough claims
            return None;
        }

        let mut frequency = Frequency::new();

        for verified_claim in verified_claims {
            frequency.update(&verified_claim)
        }

        frequency.sort_by_highest().into_iter()
            .filter(|&(_, ref count)| *count >= self.claim_threshold)
            .nth(0)
            .map(|(resolved_claim, _)| resolved_claim.clone())
    }

    fn resolve(&mut self, request: Request, claims: Vec<(Name, Signature, SerialisedClaim)>)
        -> Option<(Request, SerialisedClaim)> {
        let verified_claims = self.verify(&claims);
        self.squash(verified_claims)
            .map(|c| {
                self.claim_accumulator.delete(&request);
                (request, c)
            })
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
        #[allow(unused_variables)]
        fn get_signing_keys(&self, source: usize) {
            // TODO: can we improve on this now? compared to previous implementation
        }
    }

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
    struct TestClaim {
        value : usize
    }

}
