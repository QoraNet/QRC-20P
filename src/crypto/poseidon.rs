//! Poseidon hash function wrapper for privacy pools
//! PRODUCTION: Uses existing halo2_circuits.rs implementation for correctness

use ethereum_types::H256;
use crate::common_types::Fr;
use crate::crypto::bn256_poseidon::{Bn256Spec, Spec};
use crate::circuits::halo_circuits::{h256_to_field, field_to_h256, poseidon_permutation};

/// Poseidon hasher using production implementation from halo2_circuits
pub struct Poseidon {
    // No internal state - each hash is independent
}

impl Poseidon {
    /// Create new Poseidon hasher
    pub fn new() -> Self {
        Self {}
    }

    /// Hash two H256 values using Poseidon
    /// PRODUCTION: Uses halo2_circuits poseidon_permutation
    pub fn hash2(&mut self, left: H256, right: H256) -> H256 {
        // Convert to field elements
        let left_fr = h256_to_field(left);
        let right_fr = h256_to_field(right);

        // Initialize state with inputs
        let mut state = [left_fr, right_fr, Fr::zero()];

        // Get Poseidon constants
        let (round_constants, mds) = Bn256Spec::<3, 2>::constants();

        // Apply Poseidon permutation
        poseidon_permutation(&mut state, &round_constants, &mds);

        // Return first element as output
        field_to_h256(state[0])
    }

    /// Hash multiple H256 values using proper sponge construction
    /// PRODUCTION: Absorb/squeeze with rate=2, capacity=1
    pub fn hash_n(&mut self, inputs: &[H256]) -> H256 {
        if inputs.is_empty() {
            return H256::zero();
        }
        if inputs.len() == 1 {
            return inputs[0];
        }

        // Initialize sponge state
        let mut state = [Fr::zero(), Fr::zero(), Fr::zero()];

        // Get Poseidon constants
        let (round_constants, mds) = Bn256Spec::<3, 2>::constants();

        // Absorb phase: Process inputs in chunks of 2 (rate=2 for WIDTH=3)
        for chunk in inputs.chunks(2) {
            // XOR first input into state[0]
            state[0] += h256_to_field(chunk[0]);

            // XOR second input into state[1] if exists
            if chunk.len() > 1 {
                state[1] += h256_to_field(chunk[1]);
            }

            // Apply permutation
            poseidon_permutation(&mut state, &round_constants, &mds);
        }

        // Squeeze phase: Extract output from state[0]
        field_to_h256(state[0])
    }
}

/// Public function for hashing two H256 values using Poseidon
/// PRODUCTION: Stateless wrapper around production implementation
pub fn poseidon_hash(left: H256, right: H256) -> H256 {
    let mut hasher = Poseidon::new();
    hasher.hash2(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash2_deterministic() {
        let mut poseidon = Poseidon::new();

        let left = H256::from_low_u64_be(100);
        let right = H256::from_low_u64_be(200);

        let hash1 = poseidon.hash2(left, right);
        let hash2 = poseidon.hash2(left, right);

        // Should be deterministic
        assert_eq!(hash1, hash2);

        // Should not be zero
        assert_ne!(hash1, H256::zero());
    }

    #[test]
    fn test_hash2_order_matters() {
        let mut poseidon = Poseidon::new();

        let left = H256::from_low_u64_be(100);
        let right = H256::from_low_u64_be(200);

        let hash1 = poseidon.hash2(left, right);
        let hash2 = poseidon.hash2(right, left);

        // Different order should produce different hash
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_n_empty() {
        let mut poseidon = Poseidon::new();
        let result = poseidon.hash_n(&[]);
        assert_eq!(result, H256::zero());
    }

    #[test]
    fn test_hash_n_single() {
        let mut poseidon = Poseidon::new();
        let input = H256::from_low_u64_be(42);
        let result = poseidon.hash_n(&[input]);
        assert_eq!(result, input);
    }

    #[test]
    fn test_hash_n_multiple() {
        let mut poseidon = Poseidon::new();

        let inputs = vec![
            H256::from_low_u64_be(1),
            H256::from_low_u64_be(2),
            H256::from_low_u64_be(3),
            H256::from_low_u64_be(4),
        ];

        let hash = poseidon.hash_n(&inputs);

        // Should not be zero
        assert_ne!(hash, H256::zero());

        // Should be different from any input
        for input in &inputs {
            assert_ne!(hash, *input);
        }
    }

    #[test]
    fn test_hash_n_deterministic() {
        let mut poseidon = Poseidon::new();

        let inputs = vec![
            H256::from_low_u64_be(10),
            H256::from_low_u64_be(20),
            H256::from_low_u64_be(30),
        ];

        let hash1 = poseidon.hash_n(&inputs);
        let hash2 = poseidon.hash_n(&inputs);

        // Should be deterministic
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_public_hash() {
        let left = H256::from_low_u64_be(111);
        let right = H256::from_low_u64_be(222);

        let hash1 = poseidon_hash(left, right);
        let hash2 = poseidon_hash(left, right);

        // Should be deterministic
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, H256::zero());
    }

    #[test]
    fn test_stateless_multiple_calls() {
        let mut poseidon = Poseidon::new();

        let a = H256::from_low_u64_be(1);
        let b = H256::from_low_u64_be(2);
        let c = H256::from_low_u64_be(3);
        let d = H256::from_low_u64_be(4);

        // Multiple independent hashes
        let hash1 = poseidon.hash2(a, b);
        let hash2 = poseidon.hash2(c, d);
        let hash3 = poseidon.hash2(a, b);

        // First and third should be identical (stateless)
        assert_eq!(hash1, hash3);

        // Second should be different
        assert_ne!(hash1, hash2);
    }
}
