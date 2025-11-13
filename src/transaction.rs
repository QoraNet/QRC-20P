//! Privacy transaction validation for GO integration
//!
//! NOTE: This module only handles privacy-specific validation.
//! Base transaction handling is done by in Go.

use ethereum_types::{H256, U256};
use anyhow::{Result, anyhow};

/// Validate privacy transfer data from Go
pub fn validate_private_transfer(
    _token_id: H256,
    proof: &[u8],
    nullifiers: &[H256],
    commitments: &[H256],
) -> Result<()> {
    // TODO: These are FFI validation functions from Qora - will be reimplemented
    // use super::ffi_validation::{
    //     validate_proof,
    //     validate_nullifiers_h256,
    //     validate_commitments_h256,
    // };

    // validate_proof(proof)?;
    // validate_nullifiers_h256(nullifiers)?;
    // validate_commitments_h256(commitments)?;

    Ok(())
}

/// Validate mode switch data from Go
pub fn validate_mode_switch(
    _token_id: H256,
    from_mode: u8,
    to_mode: u8,
    amount: U256,
    proof: Option<&[u8]>,
) -> Result<()> {
    if from_mode == to_mode {
        return Err(anyhow!("Cannot switch to same mode"));
    }

    if amount == U256::zero() {
        return Err(anyhow!("Amount must be > 0"));
    }

    // Switching to private requires proof
    if to_mode == 1 && proof.is_none() {
        return Err(anyhow!("Proof required for private mode"));
    }

    if let Some(p) = proof {
        // TODO: FFI validation - use super::ffi_validation::validate_proof;
        validate_proof(p)?;
    }

    Ok(())
}
