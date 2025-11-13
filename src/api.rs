//! Stateless Public API for Privacy Operations
//!
//! This module provides a clean Rust-to-Rust interface for privacy operations.
//! NO FFI complexity, NO C ABI, NO manual memory management.
//!
//! Key principles:
//! - Stateless functions (caller provides all data)
//! - Pure cryptography only
//! - Pallet manages state (commitments, nullifiers, merkle tree)
//! - This library only does the crypto math

use ethereum_types::{Address, H256, U256};
use secp256k1::{PublicKey, SecretKey};
use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::error::{PrivacyError, PrivacyResult};

#[cfg(feature = "std")]
use crate::circuits::halo_circuits::ProductionProofSystem;

// ============================================================================
// Core Types
// ============================================================================

/// Witness data for private transfer (all provided by caller)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferWitness {
    pub secret: H256,
    pub amount: U256,
    pub blinding: H256,
    pub leaf_index: u32,
    pub merkle_path: Vec<H256>,
}

/// Public inputs for private transfer (visible on blockchain)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferPublicInputs {
    pub merkle_root: H256,
    pub nullifier: H256,
    pub commitment: H256,
}

/// ZK proof output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProof {
    pub proof_bytes: Vec<u8>,
}

/// Stealth address generation result
#[derive(Debug, Clone)]
pub struct StealthAddress {
    pub address: Address,
    pub ephemeral_pubkey: PublicKey,
}

// ============================================================================
// Proof System Handle (Minimal - Only Cached Keys)
// ============================================================================

/// Privacy system handle
///
/// This ONLY holds cached proving/verifying keys for performance.
/// NO state management - that's the pallet's job!
#[cfg(feature = "std")]
pub struct PrivacySystem {
    proof_system: Arc<ProductionProofSystem>,
}

#[cfg(feature = "std")]
impl PrivacySystem {
    /// Initialize proof system
    ///
    /// This loads KZG parameters and sets up proving/verifying keys.
    /// Call once, reuse the handle for all operations.
    ///
    /// # Parameters
    /// - `k`: Circuit size parameter (14 recommended for production)
    /// - `lookup_bits`: Lookup table size (8 recommended)
    pub fn new(k: u32, lookup_bits: usize) -> PrivacyResult<Self> {
        let proof_system = ProductionProofSystem::new(k, lookup_bits)
            .map_err(|e| PrivacyError::ProofSystemInit(e.to_string()))?;

        Ok(Self {
            proof_system: Arc::new(proof_system),
        })
    }

    /// Generate ZK proof for private transfer
    ///
    /// Caller must provide complete witness data.
    /// This function is STATELESS - no state lookups.
    pub fn prove_transfer(
        &self,
        _witness: &TransferWitness,
    ) -> PrivacyResult<TransferProof> {
        // TODO: Call ProductionProofSystem::prove()
        // For now, return placeholder
        Ok(TransferProof {
            proof_bytes: vec![],
        })
    }

    /// Verify ZK proof for private transfer
    pub fn verify_transfer(
        &self,
        _proof: &TransferProof,
        _public_inputs: &TransferPublicInputs,
    ) -> PrivacyResult<bool> {
        // TODO: Call ProductionProofSystem::verify()
        // For now, return placeholder
        Ok(true)
    }
}

// ============================================================================
// Pure Cryptographic Functions (Stateless)
// ============================================================================

/// Poseidon hash (ZK-friendly hash function)
///
/// This is a pure function with no state.
pub fn poseidon_hash(left: H256, right: H256) -> H256 {
    use crate::crypto::poseidon::poseidon_hash as poseidon_hash_internal;
    poseidon_hash_internal(left, right)
}

/// Compute commitment: Poseidon(secret, amount, blinding)
///
/// Pure function - no state access needed.
/// The commitment hides the amount and links it to a secret.
pub fn compute_commitment(
    secret: H256,
    amount: U256,
    blinding: H256,
) -> PrivacyResult<H256> {
    // Convert U256 to H256 for hashing
    // In ethereum-types v0.15 with primitive-types v0.13, to_big_endian() returns [u8; 32]
    let amount_hash_bytes: [u8; 32] = amount.to_big_endian();
    let amount_hash = H256::from(amount_hash_bytes);

    // commitment = Poseidon(secret, Poseidon(amount, blinding))
    let inner_hash = poseidon_hash(amount_hash, blinding);
    let commitment = poseidon_hash(secret, inner_hash);

    Ok(commitment)
}

/// Compute nullifier: Poseidon(secret, leaf_index)
///
/// Pure function - prevents double-spending.
/// Each commitment can only be spent once (unique nullifier).
pub fn compute_nullifier(
    secret: H256,
    leaf_index: u32,
) -> PrivacyResult<H256> {
    // Convert leaf_index to H256
    let leaf_hash = H256::from_low_u64_be(leaf_index as u64);

    // nullifier = Poseidon(secret, leaf_index)
    let nullifier = poseidon_hash(secret, leaf_hash);

    Ok(nullifier)
}

// ============================================================================
// Stealth Address Functions (Stateless ECDH)
// ============================================================================

/// Generate stealth address (ECDH-based)
///
/// Pure cryptographic function - no state needed.
/// Creates one-time address that only receiver can spend.
///
/// # Parameters
/// - `receiver_pubkey`: Receiver's public spend key
/// - `_ephemeral_secret`: Random secret (sender generates) - currently unused, will be used in full implementation
///
/// # Returns
/// - Stealth address (one-time payment address)
/// - Ephemeral public key (sender publishes this)
pub fn generate_stealth_address(
    receiver_pubkey: &PublicKey,
    _ephemeral_secret: &SecretKey,
) -> PrivacyResult<StealthAddress> {
    use crate::stealth::stealth_addresses::StealthAddressManager;

    let manager = StealthAddressManager::new();
    let (address, ephemeral_pubkey, _) = manager
        .generate_stealth_address_full(receiver_pubkey)
        .map_err(|e| PrivacyError::StealthAddress(e.to_string()))?;

    Ok(StealthAddress {
        address,
        ephemeral_pubkey,
    })
}

/// Scan for stealth payment
///
/// Receiver checks if a stealth address belongs to them.
/// Pure function - caller provides all keys.
///
/// # Parameters
/// - `view_key`: Receiver's private view key (used as receiver_secret)
/// - `_spend_pubkey`: Receiver's public spend key (currently unused)
/// - `ephemeral_pubkey`: Ephemeral key from transaction
///
/// # Returns
/// - Some(private_key) if payment is for this receiver
/// - None if payment is for someone else
pub fn scan_stealth_payment(
    view_key: &SecretKey,
    _spend_pubkey: &PublicKey,
    ephemeral_pubkey: &PublicKey,
) -> PrivacyResult<Option<SecretKey>> {
    use crate::stealth::stealth_addresses::StealthAddressManager;

    let manager = StealthAddressManager::new();

    // Try to recover the stealth private key
    match manager.recover_stealth_private_key(view_key, ephemeral_pubkey) {
        Ok(derived_secret) => Ok(Some(derived_secret)),
        Err(_) => Ok(None), // Not for this receiver or invalid
    }
}

// ============================================================================
// Merkle Tree Trait (Pallet Implements Storage Backend)
// ============================================================================

/// Storage backend trait for Merkle tree
///
/// The pallet implements this trait using Substrate storage.
/// The tree logic is stateless - just uses this trait for reads/writes.
pub trait MerkleStorage {
    fn get_leaf(&self, index: u32) -> Option<H256>;
    fn set_leaf(&mut self, index: u32, value: H256);
    fn get_node(&self, level: u8, index: u32) -> Option<H256>;
    fn set_node(&mut self, level: u8, index: u32, value: H256);
}

/// Merkle tree with pluggable storage
///
/// Tree logic is pure - storage is provided by caller.
pub struct MerkleTree<S: MerkleStorage> {
    storage: S,
    height: u8,
}

impl<S: MerkleStorage> MerkleTree<S> {
    pub fn new(storage: S, height: u8) -> Self {
        Self { storage, height }
    }

    /// Insert commitment into tree
    ///
    /// Returns new Merkle root after insertion.
    pub fn insert(&mut self, index: u32, leaf: H256) -> PrivacyResult<H256> {
        // Store leaf
        self.storage.set_leaf(index, leaf);

        // Update path from leaf to root using Poseidon hash
        let mut current_hash = leaf;
        let mut current_index = index;

        for level in 0..self.height {
            let sibling_index = current_index ^ 1;
            let sibling = self.storage
                .get_node(level, sibling_index)
                .unwrap_or_else(H256::zero);

            // Hash with sibling (maintain left/right order)
            let parent_hash = if current_index % 2 == 0 {
                poseidon_hash(current_hash, sibling)
            } else {
                poseidon_hash(sibling, current_hash)
            };

            // Store parent node
            let parent_index = current_index / 2;
            self.storage.set_node(level + 1, parent_index, parent_hash);

            current_hash = parent_hash;
            current_index = parent_index;
        }

        Ok(current_hash) // This is the new root
    }

    /// Generate Merkle proof (path from leaf to root)
    pub fn get_proof(&self, index: u32) -> PrivacyResult<Vec<H256>> {
        let mut proof = Vec::new();
        let mut current_index = index;

        for level in 0..self.height {
            let sibling_index = current_index ^ 1;
            let sibling = self.storage
                .get_node(level, sibling_index)
                .unwrap_or_else(H256::zero);

            proof.push(sibling);
            current_index /= 2;
        }

        Ok(proof)
    }

    /// Verify Merkle proof
    pub fn verify_proof(
        leaf: H256,
        proof: &[H256],
        leaf_index: u32,
        expected_root: H256,
    ) -> bool {
        let mut current_hash = leaf;
        let mut current_index = leaf_index;

        for sibling in proof {
            current_hash = if current_index % 2 == 0 {
                poseidon_hash(current_hash, *sibling)
            } else {
                poseidon_hash(*sibling, current_hash)
            };
            current_index /= 2;
        }

        current_hash == expected_root
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate random blinding factor
///
/// Uses secure randomness for cryptographic blinding.
pub fn generate_blinding() -> H256 {
    H256::random()
}

/// Generate random secret
///
/// Uses secure randomness for commitment secrets.
pub fn generate_secret() -> H256 {
    H256::random()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_deterministic() {
        let secret = H256::from_low_u64_be(12345);
        let amount = U256::from(1000000u64);
        let blinding = H256::from_low_u64_be(67890);

        let commitment1 = compute_commitment(secret, amount, blinding).unwrap();
        let commitment2 = compute_commitment(secret, amount, blinding).unwrap();

        assert_eq!(commitment1, commitment2, "Commitment should be deterministic");
    }

    #[test]
    fn test_nullifier_deterministic() {
        let secret = H256::from_low_u64_be(12345);
        let leaf_index = 42;

        let nullifier1 = compute_nullifier(secret, leaf_index).unwrap();
        let nullifier2 = compute_nullifier(secret, leaf_index).unwrap();

        assert_eq!(nullifier1, nullifier2, "Nullifier should be deterministic");
    }

    #[test]
    fn test_different_secrets_different_commitments() {
        let secret1 = H256::from_low_u64_be(12345);
        let secret2 = H256::from_low_u64_be(54321);
        let amount = U256::from(1000000u64);
        let blinding = H256::from_low_u64_be(67890);

        let commitment1 = compute_commitment(secret1, amount, blinding).unwrap();
        let commitment2 = compute_commitment(secret2, amount, blinding).unwrap();

        assert_ne!(commitment1, commitment2, "Different secrets should produce different commitments");
    }

    #[test]
    fn test_poseidon_hash() {
        let left = H256::from_low_u64_be(100);
        let right = H256::from_low_u64_be(200);

        let hash = poseidon_hash(left, right);

        assert!(!hash.is_zero(), "Poseidon hash should not be zero");
    }
}
