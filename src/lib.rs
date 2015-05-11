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

// extern crate sodiumoxide;
// extern crate cbor;
extern crate rustc_serialize;
extern crate accumulator;
extern crate sodiumoxide;
extern crate cbor;
extern crate flow;

pub type SerialisedClaim = Vec<u8>;

/// Sentinel provides a consensus mechanism on all content messages.
/// The claims made must be identical and cryptographically signed.
pub mod sentinel;
// pub mod account_sentinel;

fn check_signature(signature: &Signature, public_key: &PublicKey, claim: &SerialisedClaim)
        -> Option<SerialisedClaim> {

    match crypto::sign::verify_detached(&signature,
                                        claim,
                                        public_key) {
        true => Some(claim.clone()),
        false => None
    }
}

fn flatten_keys(sets_of_keys : &Vec<Vec<(Name, PublicKey)>>) -> Vec<(Name, PublicKey)> {
    // let mut frequency = Frequency::new();
    //
    // for keys in sets_of_keys {
    //     for key in keys {
    //         frequency.update(&key.1);
    //     }
    // }
    vec![]
}
