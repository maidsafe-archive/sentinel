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

use flow::frequency::Frequency;
// use std::collections::HashMap;

use sodiumoxide::crypto;
use sodiumoxide::crypto::sign::verify_detached;
use sodiumoxide::crypto::sign::PublicKey;
use sodiumoxide::crypto::sign::ed25519::Signature;
use sodiumoxide::crypto::asymmetricbox::curve25519xsalsa20poly1305::PUBLICKEYBYTES;
// use std::sync::mpsc::channel;
use accumulator::Accumulator;
// use rustc_serialize::{Decodable, Encodable};

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
pub struct Sentinel<'a, Request, Claim, Name> // later template also on Signature
    where Request: PartialOrd + Ord + Clone + Source,
          Claim: PartialEq + Eq + Clone,
          Name: Eq + PartialOrd + Ord + Clone {
    sender: &'a mut (GetSigningKeys + 'a),
    claim_accumulator: Accumulator<Request, (Name, Signature, Claim)>,
    keys_accumulator: Accumulator<Request, Vec<(Name, PublicKey)>>,
    claim_threshold: usize,
    keys_threshold: usize
}

impl<'a, Request, Claim, Name>
    Sentinel<'a, Request, Claim, Name>
    where Request: PartialOrd + Ord + Clone + Source,
          Claim: PartialOrd + Ord + Clone,
          Name: Eq + PartialOrd + Ord + Clone {
    /// This creates a new sentinel that will collect a minimal claim_threshold number
    /// of verified claims before attempting to merge these claims.
    /// To obtain a verified claim Sentinel needs to have received a matching public
    /// signing key. Each such a public signing key needs keys_threshold confirmations
    /// for it to be considered valid and used for verifying the signature
    /// of the corresponding claim.
    pub fn new(sender: &'a mut get_signing_keys, claim_threshold: usize, keys_threshold: usize)
        -> Sentinel<'a, Request, Claim, Name> {
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
    /// the request and the verified median of the claims are returned.
    /// Otherwise None is returned.
    pub fn add_claim(&mut self, request : Request,
                     claimant : Name, signature : Signature,
                     claim : Claim)
        // TODO: replace return option with async events pipe to different thread
        // TODO: code can be cleaned up more even by correcting ownership of Accumulator
        -> Option<(Request, Claim)> {

        match self.keys_accumulator.get(&request) {
            Some((_, set_of_keys)) => {
                self.claim_accumulator.add(request.clone(), (claimant, signature, claim))
                    .and_then(|(_, claims)| self.validate(&claims, &set_of_keys))
                    .and_then(|verified_claims| self.resolve(&verified_claims))
                    .and_then(|merged_claim| return Some((request, merged_claim)))
            },
            None => {
                self.sender.get_signing_keys();
                self.claim_accumulator.add(request, (claimant, signature, claim));
                return None;
            }
        }
    }


    /// This adds a new Claim for a given Request. The Name and the Signature provided are used to
    /// validate the Claim using independently retrieved sets of public signing keys. Resolution
    /// optionally returns the Request and median of the Claim's tuple, otherwise None.
    pub fn add_mergeable_claim(&mut self, request : Request,
                               claimant : Name, signature : Signature,
                               claim : Claim)
            -> Option<(Request, Claim)> {

        match self.keys_accumulator.get(&request) {
            Some((_, set_of_keys)) => {
                self.mergeable_claim_accumulator.add(request.clone(), (claimant, signature, claim))
                    .and_then(|(_, claims)| self.validate(&claims, &set_of_keys))
                    .and_then(|mut verified_claims| self.resolve_mergeable(&mut verified_claims))
                    .and_then(|merged_claim| return Some((request, merged_claim)))
            },
            None => {
                request.get_signing_keys();
                self.mergeable_claim_accumulator.add(request, (claimant, signature, claim));
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
        -> Option<(Request, Claim)> {

        match self.claim_accumulator.get(&request) {
            Some((_, claims)) => {
                self.keys_accumulator.add(request.clone(), keys)
                    .and_then(|(_, set_of_keys)| self.validate(&claims, &set_of_keys))
                    .and_then(|verified_claims| self.resolve(&verified_claims))
                    .and_then(|merged_claim| return Some((request, merged_claim)))
            },
            None => {
                // if no corresponding claim exists, refuse to accept keys.
                return None;
            }
        }
    }

    fn validate(&self, claims : &Vec<(Name, Signature, Claim)>,
                       sets_of_keys : &Vec<Vec<(Name, PublicKey)>> ) -> Option<Vec<Claim>> {

        let mut verified_claims = Vec::new();
        let keys = self.flatten_keys(sets_of_keys);

        if keys.len() < self.keys_threshold {
          return None;
        }

        for i in 0..claims.len() {
            for j in 0..keys.len() {
                if claims[i].0 == keys[j].0 {
                    let claim = self.check_signature(&claims[i].1, &claims[i].2, &keys[j].1);
                    if claim.is_some() {
                        verified_claims.push(claim.unwrap().clone());
                    }
                    break;
                }
            }
        }

        if verified_claims.len() >= self.claim_threshold {
          return Some(verified_claims)
        }

        None
    }

    fn resolve(&self, verified_claims : &Vec<Claim>) -> Option<Claim> {
        if verified_claims.len() < self.claim_threshold || !(self.claim_threshold >= 1) {
            return None;
        }

        for i in 0..verified_claims.len() {
            let mut total: usize = 1;
            for j in 0..verified_claims.len() {
                if j != i && verified_claims[i] == verified_claims[j] {
                    total += 1;
                }
            }

            if total >= self.claim_threshold {
                return Some(verified_claims[i].clone());
            }
        }

        None
    }

    fn resolve_mergeable(&self, verified_claims : &mut Vec<Claim>) -> Option<Claim> {
        if verified_claims.len() < self.claim_threshold || !(self.claim_threshold >= 1) {
            return None;
        }

        verified_claims.sort();
        let mid = verified_claims.len() / 2;
        Some(verified_claims[mid].clone())
    }

    fn flatten_keys(&self, sets_of_keys : &Vec<Vec<(Name, PublicKey)>>) -> Vec<(Name, PublicKey)> {
        // let mut frequency = Frequency::new();
        //
        // for keys in sets_of_keys {
        //     for key in keys {
        //         frequency.update(&key.1);
        //     }
        // }
        vec![]
    }

    fn check_signature(&self, signature: &Signature, claim: &Claim, public_key: &PublicKey)
            -> Option<Claim> {

        // let mut e = cbor::Encoder::from_memory();
        // let encoded = e.encode(&[&claim]);
        //
        // if encoded.is_ok() {
        //     let valid = crypto::sign::verify_detached(&signature, &e.as_bytes(), &public_key);
        //
        //     if valid { return Some(claim.clone()); }
        //     return None;
        // }

        None
    }
}
