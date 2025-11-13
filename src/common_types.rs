//! Common privacy types shared across modules
//! This module provides unified type definitions to avoid conflicts

use ethereum_types::{Address, H256, U256};
use serde::{Deserialize, Serialize};
use std::fmt;
use sha3::{Digest, Keccak256};
use std::str::FromStr;

// CRITICAL: Use the Fr type from halo2-base to avoid type mismatches
// All modules should import Fr from here, not directly from halo2curves
// halo2-base re-exports halo2_proofs which re-exports halo2curves
pub use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
pub use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};

// Proof version constants for migration path
/// Version 1: Application-level range validation (current production)
/// - Range validation done in privacy.rs::validate_amount()
/// - Requires TRUSTED proof generators
/// - No range constraints in ZK circuit
pub const PROOF_VERSION_V1: u8 = 1;

/// Version 2: Circuit-level range constraints (future upgrade)
/// - Range constraints enforced IN the ZK circuit
/// - Safe for UNTRUSTED proof generators
/// - Circuit validates amount ∈ [0, 2^64) without revealing it
pub const PROOF_VERSION_V2: u8 = 2;

/// Current production proof version
/// Set to V1 (application-level validation) for backward compatibility
/// Change to V2 when circuit range constraints are implemented
pub const CURRENT_PROOF_VERSION: u8 = PROOF_VERSION_V1;

/// Token identifier (hash of public and private addresses)
/// Used across all privacy modules for consistent token identification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenId(pub H256);

impl TokenId {
    /// Create token ID from addresses
    pub fn from_addresses(public: Address, private: Address) -> Self {
        let mut hasher = Keccak256::default();
        hasher.update(public.as_bytes());
        hasher.update(private.as_bytes());
        TokenId(H256::from_slice(&hasher.finalize()))
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Token({})", hex::encode(&self.0[..8]))
    }
}

/// ZK Proof structure for privacy operations
///
/// VERSIONING SUPPORT:
/// - Version field enables migration from V1 (app-level validation) to V2 (circuit-level)
/// - V1: Requires application to call validate_amount() before proof generation
/// - V2: Circuit enforces range constraints, safe for untrusted proof generators
///
/// BACKWARD COMPATIBILITY:
/// - Default version is V1 (current production behavior)
/// - Existing code continues to work without modification
/// - Optional migration to V2 when circuit range constraints are added
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// Proof version (determines validation rules)
    /// V1 = Application-level range validation (current)
    /// V2 = Circuit-level range constraints (future)
    #[serde(default = "default_proof_version")]
    pub version: u8,

    /// The actual proof bytes from Halo2
    pub proof_data: Vec<u8>,

    /// Public inputs for verification (commitment, nullifier, merkle root)
    pub public_inputs: Vec<H256>,
}

/// Default proof version for backward compatibility
/// Returns V1 (application-level validation) to maintain existing behavior
fn default_proof_version() -> u8 {
    PROOF_VERSION_V1
}

impl Proof {
    /// Create a new proof with current version (V1 - application-level validation)
    ///
    /// SECURITY NOTE: When using V1 proofs, application MUST call
    /// privacy.rs::validate_amount() BEFORE generating the proof.
    ///
    /// For V2 proofs (future), circuit enforces range constraints automatically.
    pub fn new(proof_data: Vec<u8>, public_inputs: Vec<H256>) -> Self {
        Self {
            version: CURRENT_PROOF_VERSION,
            proof_data,
            public_inputs,
        }
    }

    /// Create a proof with specific version
    ///
    /// This is primarily used for:
    /// - Testing migration between V1 and V2
    /// - Creating V2 proofs after circuit range constraints are implemented
    /// - Deserializing proofs from different versions
    ///
    /// # Arguments
    /// * `version` - PROOF_VERSION_V1 or PROOF_VERSION_V2
    /// * `proof_data` - Halo2 proof bytes
    /// * `public_inputs` - Public verification inputs
    pub fn with_version(version: u8, proof_data: Vec<u8>, public_inputs: Vec<H256>) -> Self {
        Self {
            version,
            proof_data,
            public_inputs,
        }
    }

    /// Check if this proof uses circuit-level range constraints
    ///
    /// Returns:
    /// - `false` for V1 proofs: Application MUST validate amounts
    /// - `true` for V2 proofs: Circuit enforces range constraints
    ///
    /// Use this to determine validation strategy:
    /// ```rust
    /// if !proof.has_circuit_range_constraints() {
    ///     // V1 proof: verify application called validate_amount()
    ///     // Trust required for proof generator
    /// } else {
    ///     // V2 proof: circuit enforces constraints
    ///     // Safe for untrusted proof generators
    /// }
    /// ```
    pub fn has_circuit_range_constraints(&self) -> bool {
        self.version >= PROOF_VERSION_V2
    }

    /// Check if this is a V1 proof (application-level validation)
    pub fn is_v1(&self) -> bool {
        self.version == PROOF_VERSION_V1
    }

    /// Check if this is a V2 proof (circuit-level range constraints)
    pub fn is_v2(&self) -> bool {
        self.version == PROOF_VERSION_V2
    }
}

/// Token operating mode
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum TokenMode {
    Public = 0,
    Private = 1,
}

impl TokenMode {
    pub fn is_private(&self) -> bool {
        matches!(self, TokenMode::Private)
    }

    pub fn is_public(&self) -> bool {
        matches!(self, TokenMode::Public)
    }
}

// Parse functions for FFI
/// Parse an Ethereum address from hex string
pub fn parse_address(s: &str) -> Option<Address> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Address::from_str(s).ok()
}

/// Parse a H256 hash from hex string
pub fn parse_h256(s: &str) -> Option<H256> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    H256::from_str(s).ok()
}

/// Parse a U256 from hex string
pub fn parse_u256(s: &str) -> Option<U256> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    U256::from_str_radix(s, 16).ok()
}
