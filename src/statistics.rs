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

use std::cmp::max;

pub struct Frequency<Key: PartialEq + Eq + Clone> {
    map: Vec<(Key, usize)>
}

impl<Key: PartialEq + Eq + Clone> Frequency<Key> {
    pub fn new() -> Frequency<Key> {
        Frequency {
            map: Vec::<(Key, usize)>::new()
        }
    }

    pub fn update(&mut self, key: &Key) {
        let mut fresh_key : bool = true;
        for stored_key in self.map.iter_mut() {
            if &stored_key.0 == key {
                stored_key.1 += 1;
                fresh_key = false;
                break;
            }
        }
        if fresh_key {
            self.map.push((key.clone(), 1));
        }
    }

    pub fn sort_by_highest(&mut self) -> Vec<(Key, usize)> {
        self.map.sort_by(|a,b| b.1.cmp(&a.1));
        self.map.clone()
    }
}

pub struct FrequencyKeyValue<Key: PartialEq + Eq + Clone, Value: PartialEq + Eq + Clone> {
    map: Vec<(Key, Vec<(Value, usize)>, usize)>
}

impl<Key: PartialEq + Eq + Clone, Value: PartialEq + Eq + Clone>
    FrequencyKeyValue<Key, Value> {
    pub fn new() -> FrequencyKeyValue<Key, Value> {
        FrequencyKeyValue {
            map: Vec::<(Key, Vec<(Value, usize)>, usize)>::new()
        }
    }

    pub fn update(&mut self, key: &Key, value: &Value) {
        let mut fresh_key : bool = true;
        let mut fresh_value : bool = true;
        for stored_key in self.map.iter_mut() {
            if &stored_key.0 == key {
                for stored_value in stored_key.1.iter_mut() {
                    if &stored_value.0 == value {
                        stored_value.1 += 1;
                        stored_key.2 = max(stored_key.2, stored_value.1);
                        fresh_value = false;
                        break;
                    }
                }
                if fresh_value {
                    stored_key.1.push((value.clone(), 1));
                }
                fresh_key = false;
                break;
            }
        }
        if fresh_key {
            self.map.push((key.clone(), vec![(value.clone(), 1)], 1));
        }
    }

    /// This returns every unique Key,
    /// with a Vec of all the corresponding values encountered, their respecitive count each,
    /// and the maximum count encountered for that key over all values.
    pub fn sort_by_highest(&mut self) -> Vec<(Key, Vec<(Value, usize)>, usize)> {
        self.map.sort_by(|a, b| b.2.cmp(&a.2));
        self.map.clone()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{thread_rng, Rng};

    #[test]
    fn fill_monotonic_distribution_req() {
        let mut rng = thread_rng();

        // ensure a monotonic decreasing function
        let domain_low = 0u32;
        let domain_high = 500u32;
        assert!(domain_low < domain_high);
        let mut all_counts : Vec<u32> = Vec::with_capacity(3000); // simple approx upperbound
        for _ in 0..100 {
            let x : u32 = rng.gen_range(domain_low, domain_high);
            if all_counts.contains(&x) { continue; } // avoid double counting
            let fx : f64 = x.clone() as f64;
            // use monotonic descending range of gaussian
            let y : f64 = 30f64 * (- (fx.powi(2i32) / 100000f64)).exp();
            let count : usize = y.trunc() as usize + 1;
            // duplicate the keys for
            for _ in 0usize..count { all_counts.push(x.clone()); };
        };

        // shuffle duplicated keys
        rng.shuffle(&mut all_counts[..]);
        let mut freq = Frequency::new();
        for occurance in all_counts {
            // and register each key multiple times in random order
            freq.update(&occurance);
        };
        // sort the counts
        let ordered_counts = freq.sort_by_highest();
        let mut max_count = 31usize;
        for value in ordered_counts {
            let fx : f64 = value.0.clone() as f64;
            let y : f64 = 30f64 * (- (fx.powi(2i32) / 100000f64)).exp();
            let count : usize = y.trunc() as usize + 1;
            // because we started with random keys whos occurance monotonically decreased
            // for increasing key, the keys should now increase, as the count decreases.
            assert_eq!(value.1, count);
            assert!(value.1 <= max_count);
            max_count = value.1.clone();
        };
    }

    #[test]
    fn fill_monotonic_distribution_freq_key_val() {
        let mut rng = thread_rng();

        // ensure a monotonic decreasing function
        let domain_low = 0u32;
        let domain_high = 500u32;
        assert!(domain_low < domain_high);
        let mut all_counts : Vec<u32> = Vec::with_capacity(3000); // simple approx upperbound
        for _ in 0..100 {
            let x : u32 = rng.gen_range(domain_low, domain_high);
            if all_counts.contains(&x) { continue; } // avoid double counting
            let fx : f64 = x.clone() as f64;
            // use monotonic descending range of gaussian
            let y : f64 = 30f64 * (- (fx.powi(2i32) / 100000f64)).exp();
            let count : usize = y.trunc() as usize + 1;
            // duplicate the keys for
            for _ in 0usize..count { all_counts.push(x.clone()); };
        };

        // shuffle duplicated keys
        rng.shuffle(&mut all_counts[..]);
        let mut freq = FrequencyKeyValue::new();
        for occurance in all_counts {
            // and register each key multiple times in random order
            freq.update(&occurance, &occurance);
        };
        // sort the counts
        let ordered_counts = freq.sort_by_highest();
        let mut max_count = 31usize;
        for value in ordered_counts {
            let fx : f64 = value.0.clone() as f64;
            let y : f64 = 30f64 * (- (fx.powi(2i32) / 100000f64)).exp();
            let count : usize = y.trunc() as usize + 1;
            // because we started with random keys whos occurance monotonically decreased
            // for increasing key, the keys should now increase, as the count decreases.
            assert_eq!(value.2, count);
            assert!(value.2 <= max_count);
            max_count = value.2.clone();
        };
    }

}
