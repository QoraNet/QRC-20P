//! Halo2 ZK-SNARK Circuits
//!
//! This module contains the Halo2 circuit implementation for privacy transactions.
//!
//! ## Source
//! Adapted from: `Qora-Blockcina-V2/Rust-FFI/src/halo2_circuits.rs`
//!


// Re-export common_types and crypto modules for use by halo_circuits
// (since Qora code uses super::common_types)
pub use crate::common_types;
pub use crate::crypto::bn256_poseidon;

pub mod halo_circuits;

// Re-export all items from halo_circuits
pub use halo_circuits::*;
