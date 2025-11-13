//! Cryptographic Primitives
//!
//! This module contains ZK-friendly hash functions and curve operations.
//!
//! ## Modules
//! - `poseidon` - Poseidon hash implementation
//! - `bn256_poseidon` - BN256 curve-specific Poseidon spec
//!
//! ## Source
//! Adapted from Qora-Blockcina-V2 production code

// Poseidon hash modules
pub mod poseidon;
pub mod bn256_poseidon;

// Re-export commonly used items
pub use poseidon::*;
pub use bn256_poseidon::*;

// Re-export common types from root for convenience
pub use crate::common_types;
