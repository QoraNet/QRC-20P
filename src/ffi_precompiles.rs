//! FFI exports for EVM precompiles
//! These functions are called directly during EVM execution

use std::slice;
use std::ptr;
use std::sync::{Arc, Mutex, Once};
use ethereum_types::H256;
use anyhow::Result;
use crate::crypto::poseidon::poseidon_hash as poseidon_hash_fn;
use crate::circuits::halo_circuits::ProductionProofSystem;

// Global proof system (initialized once)
static INIT: Once = Once::new();
static mut PROOF_SYSTEM: Option<Arc<ProductionProofSystem>> = None;

fn get_proof_system() -> Result<Arc<ProductionProofSystem>> {
    unsafe {
        INIT.call_once(|| {
            match ProductionProofSystem::new(17, 8) {
                Ok(system) => PROOF_SYSTEM = Some(Arc::new(system)),
                Err(_) => {}
            }
        });

        PROOF_SYSTEM.clone().ok_or_else(|| anyhow::anyhow!("Proof system not initialized"))
    }
}

/// Poseidon hash precompile (0x0D)
///
/// # Safety
/// Caller must ensure pointers are valid and input_len matches input buffer size
#[no_mangle]
pub unsafe extern "C" fn poseidon_hash(
    input: *const u8,
    input_len: u32,
    output: *mut u8,
) -> i32 {
    if input.is_null() || output.is_null() || input_len == 0 {
        return -1;
    }

    let input_slice = slice::from_raw_parts(input, input_len as usize);

    // For now, hash pairs of 32-byte values
    // If input is not 64 bytes, pad or truncate
    let left = if input_slice.len() >= 32 {
        H256::from_slice(&input_slice[0..32])
    } else {
        H256::zero()
    };

    let right = if input_slice.len() >= 64 {
        H256::from_slice(&input_slice[32..64])
    } else {
        H256::zero()
    };

    let hash = poseidon_hash_fn(left, right);
    ptr::copy_nonoverlapping(hash.as_ptr(), output, 32);
    0 // Success
}

/// ZK proof verification precompile (0x0E)
///
/// # Safety
/// Caller must ensure pointers are valid and proof_len matches proof buffer size
#[no_mangle]
pub unsafe extern "C" fn verify_zk_proof(
    proof: *const u8,
    proof_len: u32,
) -> i32 {
    if proof.is_null() || proof_len == 0 {
        return -1; // Invalid input
    }

    let proof_slice = slice::from_raw_parts(proof, proof_len as usize);

    // Proof format: [proof_bytes][commitment_32bytes][nullifier_32bytes]
    // Last 64 bytes are commitment + nullifier
    if proof_slice.len() < 64 {
        return -1; // Invalid proof format
    }

    let proof_len = proof_slice.len() - 64;
    let proof_bytes = &proof_slice[0..proof_len];
    let commitment = H256::from_slice(&proof_slice[proof_len..proof_len + 32]);
    let nullifier = H256::from_slice(&proof_slice[proof_len + 32..]);

    // Get proof system and verify
    match get_proof_system() {
        Ok(system) => {
            match system.verify(proof_bytes, commitment, nullifier) {
                Ok(true) => 0,  // Proof valid
                Ok(false) => 1, // Proof invalid
                Err(_) => -2,   // Verification error
            }
        }
        Err(_) => -3, // Proof system initialization failed
    }
}

/// Universal switch precompile (0x20)
/// Handles public <-> private mode switching
///
/// # Safety
/// Caller must ensure all pointers are valid and lengths match buffer sizes
#[no_mangle]
pub unsafe extern "C" fn process_universal_switch(
    input: *const u8,
    input_len: u32,
    output: *mut u8,
    output_len: *mut u32,
) -> i32 {
    if input.is_null() || output.is_null() || output_len.is_null() || input_len < 4 {
        return -1; // Invalid input
    }

    let input_slice = slice::from_raw_parts(input, input_len as usize);
    let max_output_len = *output_len as usize;

    // Extract function selector (first 4 bytes)
    let selector = &input_slice[0..4];
    let call_data = &input_slice[4..];

    // Process based on function selector
    let result = match selector {
        // switchToPublicInstant(bytes,bytes32,address,uint256,bytes32)
        [0x8a, 0x7c, 0x2f, 0x1d] => {
            process_switch_to_public_instant(call_data)
        }
        // switchToPrivateInstant(uint256,bytes32,uint256)
        [0x3b, 0x9e, 0x4a, 0x8c] => {
            process_switch_to_private_instant(call_data)
        }
        // autoRegisterERC20(address) - Auto dual-mode registration
        [0xAA, 0xBB, 0xCC, 0xDD] => {
            process_auto_register_erc20(call_data)
        }
        _ => Err(format!("Unknown function selector: {:?}", selector)),
    };

    match result {
        Ok(output_data) => {
            if output_data.len() > max_output_len {
                return -3; // Output buffer too small
            }
            ptr::copy_nonoverlapping(output_data.as_ptr(), output, output_data.len());
            *output_len = output_data.len() as u32;
            0 // Success
        }
        Err(_) => -2, // Processing failed
    }
}

/// Process instant public -> private switch
/// Input: proof (variable), nullifier (32), recipient (20), amount (32), root (32)
fn process_switch_to_public_instant(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 116 {
        return Err("Input too short".to_string());
    }

    // Parse inputs (simplified - in production need proper ABI decoding)
    // For now, just validate proof format and return success

    // Return encoded boolean (true = success)
    let mut result = vec![0u8; 32];
    result[31] = 1; // true
    Ok(result)
}

/// Process instant private -> public switch
/// Input: amount (32), commitment (32), fee (32)
fn process_switch_to_private_instant(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 96 {
        return Err("Input too short".to_string());
    }

    // Parse inputs (simplified - in production need proper ABI decoding)
    // For now, just validate and return success

    // Return encoded commitment hash
    let mut result = vec![0u8; 32];
    // In production, this would be the actual commitment added to Merkle tree
    result[31] = 1;
    Ok(result)
}

/// Process auto-registration of ERC20 for dual-mode privacy
/// Input: token_address (32 bytes padded)
fn process_auto_register_erc20(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 32 {
        return Err("Input too short".to_string());
    }

    // Extract token address (last 20 bytes of 32-byte padded input)
    let _token_address = &data[12..32];

    // In production:
    // 1. Generate QRC20Private contract bytecode
    // 2. Deploy QRC20Private contract
    // 3. Register pair in UniversalSwitch registry
    // 4. Return private contract address

    // For now, return success marker
    let mut result = vec![0u8; 32];
    result[31] = 1; // Success
    Ok(result)
}
