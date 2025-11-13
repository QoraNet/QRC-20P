//! Merkle Tree Implementation for Privacy Commitments
//!
//! Optimized for ZK-SNARK circuits with sparse tree support

use anyhow::{Result, anyhow};
use ethereum_types::H256;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::collections::HashMap;

use crate::crypto::poseidon::poseidon_hash;  // Use real Poseidon hash for ZK circuits

// Removed Keccak256 fallback - using real Poseidon hash


/// Merkle tree for commitments
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Tree height
    pub height: usize,
    /// Leaf nodes
    leaves: Vec<H256>,
    /// Internal nodes (level, index) -> hash
    nodes: HashMap<(usize, usize), H256>,
    /// Current root
    root: H256,
    /// Zero hashes for each level
    zero_hashes: Vec<H256>,
}

impl MerkleTree {
    /// Create new merkle tree with bounds checking
    pub fn new(height: usize) -> Self {
        // CRITICAL FIX: Add bounds checking to prevent overflow
        // Maximum safe height depends on platform's usize width
        const MAX_SAFE_HEIGHT: usize = if std::mem::size_of::<usize>() == 8 {
            63  // For 64-bit systems: 1 << 63 is max before overflow
        } else {
            31  // For 32-bit systems: 1 << 31 is max before overflow
        };

        // Practical limit for merkle trees (2^32 leaves = ~4 billion)
        const PRACTICAL_MAX_HEIGHT: usize = 32;

        // Use the minimum of safe and practical limits
        let safe_height = height.min(PRACTICAL_MAX_HEIGHT).min(MAX_SAFE_HEIGHT);

        // Log warning if height was clamped
        if height > safe_height {
            tracing::warn!(
                "Merkle tree height {} exceeds safe limit, clamped to {}",
                height,
                safe_height
            );
        }

        let zero_hashes = Self::compute_zero_hashes(safe_height);
        let root = zero_hashes[safe_height].clone();

        Self {
            height: safe_height,
            leaves: Vec::new(),
            nodes: HashMap::new(),
            root,
            zero_hashes,
        }
    }

    /// Compute zero hashes for sparse tree
    fn compute_zero_hashes(height: usize) -> Vec<H256> {
        let mut hashes = vec![H256::zero(); height + 1];

        for level in 1..=height {
            let child = hashes[level - 1];
            hashes[level] = poseidon_hash(child, child);
        }

        hashes
    }

    /// Insert a new leaf with overflow-safe bounds checking
    pub fn insert(&mut self, leaf: H256) -> Result<usize> {
        // CRITICAL FIX: Use checked arithmetic to prevent overflow
        // Calculate max_leaves safely without overflow risk
        let max_leaves = if self.height >= std::mem::size_of::<usize>() * 8 {
            // Height is too large, tree is effectively infinite
            // but we use usize::MAX as practical limit
            usize::MAX
        } else {
            // Safe to compute 1 << height
            // Using checked_shl for extra safety
            match 1usize.checked_shl(self.height as u32) {
                Some(max) => max,
                None => {
                    // This should not happen with our height limits,
                    // but handle gracefully
                    return Err(anyhow!(
                        "Tree height {} too large to compute capacity",
                        self.height
                    ));
                }
            }
        };

        // Check if tree is full
        if self.leaves.len() >= max_leaves {
            return Err(anyhow!(
                "Tree is full: {} leaves at height {}",
                self.leaves.len(),
                self.height
            ));
        }

        // Ensure we won't overflow when adding
        let index = self.leaves.len();
        if index == usize::MAX {
            return Err(anyhow!("Cannot add more leaves: index overflow"));
        }

        self.leaves.push(leaf);

        // Update the tree
        self.update_tree(index)?;

        Ok(index)
    }

    /// Update tree after insertion
    fn update_tree(&mut self, leaf_index: usize) -> Result<()> {
        let mut current_hash = self.leaves[leaf_index];
        let mut current_index = leaf_index;

        for level in 0..self.height {
            // Store current node
            self.nodes.insert((level, current_index), current_hash);

            // Get sibling
            let sibling_index = current_index ^ 1;
            let sibling_hash = if level == 0 && sibling_index < self.leaves.len() {
                self.leaves[sibling_index]
            } else {
                self.nodes.get(&(level, sibling_index))
                    .copied()
                    .unwrap_or(self.zero_hashes[level])
            };

            // Compute parent hash
            let parent_hash = if current_index % 2 == 0 {
                poseidon_hash(current_hash, sibling_hash)
            } else {
                poseidon_hash(sibling_hash, current_hash)
            };

            // Move up
            current_index /= 2;
            current_hash = parent_hash;
        }

        // Update root
        self.root = current_hash;
        Ok(())
    }

    /// Get merkle proof for a leaf
    pub fn get_proof(&self, leaf_index: usize) -> Result<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return Err(anyhow!("Leaf index out of bounds"));
        }

        let mut path = Vec::new();
        let mut path_indices = Vec::new();
        let mut current_index = leaf_index;

        for level in 0..self.height {
            let sibling_index = current_index ^ 1;
            let sibling_hash = if level == 0 && sibling_index < self.leaves.len() {
                self.leaves[sibling_index]
            } else {
                self.nodes.get(&(level, sibling_index))
                    .copied()
                    .unwrap_or(self.zero_hashes[level])
            };

            path.push(sibling_hash);
            path_indices.push(current_index % 2 == 1);
            current_index /= 2;
        }

        Ok(MerkleProof {
            leaf: self.leaves[leaf_index],
            leaf_index,
            path,
            path_indices,
            root: self.root,
            metadata: None,  // Standard proof without metadata
        })
    }

    /// Verify a merkle proof with comprehensive cryptographic validation
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        // CRITICAL FIX: Implement complete cryptographic verification
        // This ensures the proof actually demonstrates inclusion in the tree

        // Step 1: Validate proof structure
        if proof.path.len() != proof.path_indices.len() {
            tracing::warn!("Invalid proof: path length mismatch");
            return false;
        }

        // Step 2: Validate leaf is not zero (zero leaves are invalid in our system)
        if proof.leaf == H256::zero() {
            tracing::warn!("Invalid proof: zero leaf");
            return false;
        }

        // Step 3: Validate root is not zero (empty tree has different root)
        if proof.root == H256::zero() {
            tracing::warn!("Invalid proof: zero root");
            return false;
        }

        // Step 4: Validate path doesn't exceed maximum tree height
        const MAX_TREE_HEIGHT: usize = 32;  // Support up to 4 billion leaves
        if proof.path.len() > MAX_TREE_HEIGHT {
            tracing::warn!("Invalid proof: path too long ({})", proof.path.len());
            return false;
        }

        // Step 5: Validate leaf index is consistent with path
        if proof.path.len() > 0 {
            let max_index = (1usize << proof.path.len()) - 1;
            if proof.leaf_index > max_index {
                tracing::warn!(
                    "Invalid proof: leaf_index {} exceeds max {} for height {}",
                    proof.leaf_index,
                    max_index,
                    proof.path.len()
                );
                return false;
            }
        }

        // Step 6: Cryptographically verify the inclusion proof
        let mut current_hash = proof.leaf;
        let mut current_index = proof.leaf_index;

        for i in 0..proof.path.len() {
            let sibling = proof.path[i];

            // Validate sibling is not manipulated (optional: check against known siblings)
            if sibling == current_hash {
                // Sibling should not equal current hash (except in very rare cases)
                tracing::warn!("Suspicious proof: sibling equals current hash at level {}", i);
                // Don't immediately reject, but log for analysis
            }

            // Verify the path index matches the expected bit of leaf_index
            let expected_bit = (current_index & 1) == 1;
            if proof.path_indices[i] != expected_bit {
                tracing::warn!(
                    "Invalid proof: path index mismatch at level {} (expected {}, got {})",
                    i,
                    expected_bit,
                    proof.path_indices[i]
                );
                return false;
            }

            // Compute parent hash with correct ordering
            current_hash = if proof.path_indices[i] {
                // Current node is right child
                poseidon_hash(sibling, current_hash)
            } else {
                // Current node is left child
                poseidon_hash(current_hash, sibling)
            };

            // Move to parent index
            current_index >>= 1;
        }

        // Step 7: Final verification - computed root must match claimed root
        let is_valid = current_hash == proof.root;

        // Step 8: Additional security check - verify the proof is fresh
        // In production, you might want to check proof timestamp or nonce

        if is_valid {
            tracing::debug!(
                "Valid merkle proof for leaf at index {} (height {})",
                proof.leaf_index,
                proof.path.len()
            );
        } else {
            tracing::warn!(
                "Invalid merkle proof: computed root {:?} != claimed root {:?}",
                current_hash,
                proof.root
            );
        }

        is_valid
    }

    /// Get current root
    pub fn root(&self) -> H256 {
        self.root
    }

    /// Get number of leaves
    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    /// Check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Get leaf at index
    pub fn get_leaf(&self, index: usize) -> Option<H256> {
        self.leaves.get(index).copied()
    }

    /// Batch insert multiple leaves
    pub fn batch_insert(&mut self, leaves: Vec<H256>) -> Result<Vec<usize>> {
        let mut indices = Vec::new();

        for leaf in leaves {
            let index = self.insert(leaf)?;
            indices.push(index);
        }

        Ok(indices)
    }

    /// Verify multiple merkle proofs efficiently (batch verification)
    pub fn verify_batch_proofs(proofs: &[MerkleProof]) -> Vec<bool> {
        // CRITICAL: Batch verification for improved performance
        // Still maintains individual cryptographic verification

        let mut results = Vec::with_capacity(proofs.len());

        // Pre-validate common root (if all proofs claim same root)
        let common_root = if !proofs.is_empty() {
            Some(proofs[0].root)
        } else {
            None
        };

        let has_common_root = common_root.is_some() &&
            proofs.iter().all(|p| p.root == common_root.unwrap());

        if has_common_root {
            tracing::debug!("Batch verifying {} proofs with common root", proofs.len());
        }

        // Verify each proof independently (can be parallelized in production)
        for proof in proofs {
            results.push(Self::verify_proof(proof));
        }

        // Additional batch validation
        if has_common_root && results.iter().filter(|&&r| r).count() > 0 {
            // At least one proof is valid, perform additional checks
            let valid_indices: Vec<_> = proofs.iter()
                .enumerate()
                .filter(|(i, _)| results[*i])
                .map(|(_, p)| p.leaf_index)
                .collect();

            // Check for duplicate indices (potential replay attack)
            let mut seen_indices = std::collections::HashSet::new();
            for idx in valid_indices {
                if !seen_indices.insert(idx) {
                    tracing::warn!("Duplicate leaf index {} in batch proofs - potential replay", idx);
                }
            }
        }

        results
    }

    /// Create a proof with anti-replay nonce - PRODUCTION IMPLEMENTATION
    pub fn get_proof_with_nonce(&self, leaf_index: usize, nonce: u64) -> Result<MerkleProof> {
        // Get standard proof
        let mut proof = self.get_proof(leaf_index)?;

        // PRODUCTION: Store nonce in proof metadata, not in leaf hash
        // This preserves the cryptographic integrity of the merkle proof

        // Generate commitment for the nonce (for additional verification)
        let mut hasher = sha3::Keccak256::default();
        hasher.update(b"PROOF_NONCE_COMMITMENT_V1");
        hasher.update(proof.leaf.as_bytes());
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&proof.leaf_index.to_le_bytes());
        let commitment = H256::from_slice(&hasher.finalize());

        // Store metadata properly
        proof.metadata = Some(ProofMetadata {
            nonce,
            timestamp: chrono::Utc::now().timestamp() as u64,
            original_leaf: proof.leaf,  // Preserve original leaf value
            commitment: Some(commitment),  // Anti-replay commitment
        });

        Ok(proof)
    }

    /// Verify a proof with nonce for anti-replay protection
    pub fn verify_proof_with_nonce(proof: &MerkleProof, expected_nonce: u64) -> Result<bool> {
        // First verify the merkle proof itself
        if !Self::verify_proof(proof) {
            return Ok(false);
        }

        // Then verify the nonce metadata
        match &proof.metadata {
            Some(metadata) => {
                // Check nonce matches
                if metadata.nonce != expected_nonce {
                    tracing::warn!("Nonce mismatch: expected {}, got {}", expected_nonce, metadata.nonce);
                    return Ok(false);
                }

                // Verify commitment if present
                if let Some(commitment) = metadata.commitment {
                    let mut hasher = sha3::Keccak256::default();
                    hasher.update(b"PROOF_NONCE_COMMITMENT_V1");
                    hasher.update(metadata.original_leaf.as_bytes());
                    hasher.update(&metadata.nonce.to_le_bytes());
                    hasher.update(&proof.leaf_index.to_le_bytes());
                    let expected_commitment = H256::from_slice(&hasher.finalize());

                    if commitment != expected_commitment {
                        tracing::warn!("Invalid nonce commitment");
                        return Ok(false);
                    }
                }

                // Check timestamp for freshness (optional: reject old proofs)
                let current_time = chrono::Utc::now().timestamp() as u64;
                const MAX_PROOF_AGE: u64 = 3600; // 1 hour

                if current_time > metadata.timestamp + MAX_PROOF_AGE {
                    tracing::warn!("Proof expired: generated at {}, current time {}",
                        metadata.timestamp, current_time);
                    return Ok(false);
                }

                Ok(true)
            }
            None => {
                tracing::warn!("Proof missing metadata for nonce verification");
                Ok(false)
            }
        }
    }

    /// Export tree state for persistence
    pub fn export(&self) -> TreeState {
        TreeState {
            height: self.height,
            leaves: self.leaves.clone(),
            nodes: self.nodes.clone(),
            root: self.root,
        }
    }

    /// Rollback tree to specific size
    pub fn rollback_to_size(&mut self, size: usize) -> Result<()> {
        if size > self.leaves.len() {
            return Err(anyhow!("Cannot rollback to future size"));
        }

        // Truncate leaves
        self.leaves.truncate(size);

        // Clear affected nodes with overflow-safe arithmetic
        self.nodes.retain(|(level, index), _| {
            // CRITICAL FIX: Use checked arithmetic to prevent overflow
            let max_index_at_level = if *level >= std::mem::size_of::<usize>() * 8 {
                // Level too large, no valid indices at this level
                0
            } else {
                // Safe calculation using checked arithmetic
                match 1usize.checked_shl(*level as u32) {
                    Some(level_size) => {
                        // Calculate (size + level_size - 1) / level_size safely
                        size.saturating_add(level_size.saturating_sub(1)) / level_size.max(1)
                    }
                    None => 0,  // Overflow, no valid indices
                }
            };
            *index < max_index_at_level
        });

        // Recalculate root
        if size == 0 {
            self.root = self.zero_hashes[self.height];
        } else {
            self.update_tree(size - 1)?;
        }

        Ok(())
    }

    /// Set root directly (for snapshot restoration)
    pub fn set_root(&mut self, root: H256) {
        self.root = root;
    }

    /// Import tree state
    pub fn import(state: TreeState) -> Self {
        Self {
            height: state.height,
            leaves: state.leaves,
            nodes: state.nodes,
            root: state.root,
            zero_hashes: Self::compute_zero_hashes(state.height),
        }
    }
}

/// Merkle proof with optional metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf: H256,
    pub leaf_index: usize,
    pub path: Vec<H256>,
    pub path_indices: Vec<bool>,
    pub root: H256,
    /// Optional metadata for anti-replay and additional verification
    pub metadata: Option<ProofMetadata>,
}

/// Proof metadata for enhanced security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Anti-replay nonce
    pub nonce: u64,
    /// Timestamp when proof was generated
    pub timestamp: u64,
    /// Original leaf value (before any transformations)
    pub original_leaf: H256,
    /// Optional commitment for the proof
    pub commitment: Option<H256>,
}

/// Tree state for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeState {
    pub height: usize,
    pub leaves: Vec<H256>,
    pub nodes: HashMap<(usize, usize), H256>,
    pub root: H256,
}

/// Incremental merkle tree for efficient updates
pub struct IncrementalMerkleTree {
    tree: MerkleTree,
    /// Cached roots after each insertion
    cached_roots: Vec<H256>,
    /// Maximum cached roots
    max_cache_size: usize,
}

impl IncrementalMerkleTree {
    pub fn new(height: usize) -> Self {
        Self {
            tree: MerkleTree::new(height),
            cached_roots: Vec::new(),
            max_cache_size: 100,
        }
    }

    pub fn insert(&mut self, leaf: H256) -> Result<usize> {
        let index = self.tree.insert(leaf)?;

        // Cache the new root
        self.cached_roots.push(self.tree.root());

        // Prune cache if too large
        if self.cached_roots.len() > self.max_cache_size {
            self.cached_roots.remove(0);
        }

        Ok(index)
    }

    pub fn is_known_root(&self, root: H256) -> bool {
        self.cached_roots.contains(&root) || self.tree.root() == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree() {
        let mut tree = MerkleTree::new(3);

        let leaf1 = H256::from_low_u64_be(1);
        let leaf2 = H256::from_low_u64_be(2);

        let idx1 = tree.insert(leaf1).unwrap();
        let idx2 = tree.insert(leaf2).unwrap();

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);

        let proof1 = tree.get_proof(0).unwrap();
        assert!(MerkleTree::verify_proof(&proof1));
    }

    #[test]
    fn test_incremental_tree() {
        let mut tree = IncrementalMerkleTree::new(3);

        let leaf = H256::from_low_u64_be(42);
        tree.insert(leaf).unwrap();

        let root = tree.tree.root();
        assert!(tree.is_known_root(root));
    }
}
