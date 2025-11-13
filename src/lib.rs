//! QoraNet Privacy Library - Production-Ready ZK Privacy for QoraNet Blockcian L1
//!
//! This library contains production-grade privacy primitives adapted from Qora:
//! - Halo2 ZK-SNARK circuits (no trusted setup)
//! - Poseidon hash (ZK-friendly)
//! - Stealth addresses (ECDH-based)
//! - Sparse Merkle trees
//! - Dandelion++ network privacy
//! - Amount splitting and mixing
//!
//! # Architecture
//!
//! This library provides a **stateless Rust-to-Rust API** for privacy operations.
//! State management is handled by the Substrate pallet, not this library.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use qoranet_privacy::{PrivacySystem, compute_commitment, compute_nullifier};
//!
//! // Initialize proof system (once, reuse handle)
//! let privacy_system = PrivacySystem::new(14, 8)?;
//!
//! // Compute commitment (stateless)
//! let commitment = compute_commitment(secret, amount, blinding)?;
//!
//! // Generate proof (stateless, caller provides witness)
//! let proof = privacy_system.prove_transfer(&witness)?;
//! ```

// Core type definitions
pub mod common_types;

// ============================================================================
// NEW RUST-TO-RUST API (Stateless, Clean)
// ============================================================================

pub mod api;       // ✅ NEW: Stateless public API
pub mod error;     // ✅ NEW: Proper error types

// Cryptographic primitives
pub mod crypto {
    pub mod bn256_poseidon;
    pub mod poseidon;
    pub use bn256_poseidon::*;
    pub use poseidon::*;
}

// ZK-SNARK circuits and proofs
pub mod circuits {
    pub mod halo_circuits;
    pub use halo_circuits::*;
}

pub mod zk_proofs;

// Privacy components
pub mod stealth {
    pub mod stealth_addresses;
    pub use stealth_addresses::*;
}

pub mod merkle {
    pub mod merkle_tree;
    pub use merkle_tree::*;
}

pub mod nullifiers {
    pub mod secure_privacy;
    pub use secure_privacy::*;
}

// Network privacy and mixing features - only for P2P node, not pallet
// These modules use tokio async runtime and are not needed for pallet ZK proofs
#[cfg(feature = "network")]
pub mod amount_splitter;

#[cfg(feature = "network")]
pub mod network_privacy;

pub mod key_management;
pub mod security_utils;

// FFI modules for C-compatible exports (for separate nightly/stable build)
pub mod ffi;
pub mod ffi_precompiles;
// ffi_dual_token not needed - core FFI functions are in ffi.rs
// pub mod ffi_dual_token;

// Note: universal_switch, token_factory, transaction are blockchain/backend modules
// They depend on missing stubs/backend modules and are NOT ready for compilation yet
// These will be integrated into pallet-privacy later when backend is ported
// pub mod universal_switch;
// pub mod token_factory;
// pub mod transaction;

// ============================================================================
// PUBLIC API RE-EXPORTS
// ============================================================================

// Re-export new stateless API (primary interface)
pub use api::*;
pub use error::*;

// Re-export commonly used types
pub use common_types::*;
pub use zk_proofs::*;

#[cfg(feature = "network")]
pub use amount_splitter::{AmountMixer, AmountSplitter};

// Test modules (to be added later)
// #[cfg(test)]
// mod test_constraints;
// #[cfg(test)]
// mod test_circuit_proof;
// #[cfg(test)]
// mod test_halo2_keygen;
