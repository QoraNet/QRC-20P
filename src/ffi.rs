//! Minimal FFI exports for Rust-to-Go bridge
//! Exports only the 4 functions needed by pallet-privacy

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use std::sync::Arc;

use ethereum_types::{H256, U256};
use hex;

use crate::circuits::halo_circuits::ProductionProofSystem;

/// Magic number for handle validation
const PRIVACY_HANDLE_MAGIC: u64 = 0xDEADBEEF_CAFEBABE;

/// Privacy system handle wrapper with magic number
#[repr(C)]
pub struct PrivacySystemHandleWrapper {
    magic: u64,
    pub(crate) handle: PrivacySystemHandle,
    created_at: u64,
}

/// Minimal privacy system handle
pub struct PrivacySystemHandle {
    pub(crate) proof_system: Arc<ProductionProofSystem>,
}

/// Safely validate and dereference a handle wrapper pointer
pub(crate) unsafe fn validate_handle_wrapper(wrapper_ptr: *const PrivacySystemHandleWrapper) -> Option<&'static PrivacySystemHandleWrapper> {
    if wrapper_ptr.is_null() {
        return None;
    }

    // Check alignment
    if wrapper_ptr.align_offset(std::mem::align_of::<PrivacySystemHandleWrapper>()) != 0 {
        return None;
    }

    // Safely check if memory is accessible by reading magic number
    let magic_ptr = wrapper_ptr as *const u64;

    // Use volatile read to prevent optimization and catch memory errors
    let magic_value = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        std::ptr::read_volatile(magic_ptr)
    })) {
        Ok(val) => val,
        Err(_) => return None,
    };

    // Validate magic number
    if magic_value != PRIVACY_HANDLE_MAGIC {
        return None;
    }

    // Now safe to dereference the full struct
    Some(&*wrapper_ptr)
}

/// Safely validate and dereference a mutable handle wrapper pointer
pub(crate) unsafe fn validate_handle_wrapper_mut(wrapper_ptr: *mut PrivacySystemHandleWrapper) -> Option<&'static mut PrivacySystemHandleWrapper> {
    validate_handle_wrapper(wrapper_ptr as *const _).map(|_| &mut *wrapper_ptr)
}

/// Initialize privacy system (PrivacySystem::new)
///
/// # Arguments
/// * `k` - Circuit size parameter (e.g., 14 for 2^14 rows)
/// * `lookup_bits` - Lookup table bit size (e.g., 8)
///
/// # Returns
/// * Handle pointer on success, null on failure
///
/// # Safety
/// This function catches panics to prevent unwinding across FFI boundary
#[no_mangle]
pub extern "C" fn privacy_system_new(k: u32, lookup_bits: usize) -> *mut std::os::raw::c_void {
    eprintln!("🔍 FFI: privacy_system_new called with k={}, lookup_bits={}", k, lookup_bits);

    // ✅ CRITICAL FIX: Catch panics to prevent crossing FFI boundary
    let result = std::panic::catch_unwind(|| {
        ProductionProofSystem::new(k, lookup_bits)
    });

    let proof_system = match result {
        Ok(Ok(ps)) => {
            eprintln!("✅ FFI: Privacy system initialized successfully");
            Arc::new(ps)
        }
        Ok(Err(e)) => {
            eprintln!("❌ FFI ERROR: Failed to initialize proof system: {}", e);
            eprintln!("❌ FFI ERROR: Error details: {:?}", e);
            return ptr::null_mut();
        }
        Err(panic_info) => {
            eprintln!("❌ FFI PANIC: Privacy system initialization panicked!");
            if let Some(s) = panic_info.downcast_ref::<&str>() {
                eprintln!("❌ FFI PANIC: Panic message: {}", s);
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                eprintln!("❌ FFI PANIC: Panic message: {}", s);
            } else {
                eprintln!("❌ FFI PANIC: Unknown panic type");
            }
            return ptr::null_mut();
        }
    };

    let handle = PrivacySystemHandle { proof_system };

    let wrapper = Box::new(PrivacySystemHandleWrapper {
        magic: PRIVACY_HANDLE_MAGIC,
        handle,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs(),
    });

    let ptr = Box::into_raw(wrapper) as *mut std::os::raw::c_void;
    eprintln!("✅ FFI: Returning handle pointer: {:?}", ptr);
    ptr
}

/// Compute commitment
///
/// # Arguments
/// * `secret` - 32-byte secret
/// * `amount` - Amount as u64
/// * `blinding` - 32-byte blinding factor
/// * `commitment_out` - Output buffer for 32-byte commitment
///
/// # Returns
/// * 0 on success, -1 on failure
#[no_mangle]
pub extern "C" fn compute_commitment(
    secret: *const u8,
    amount: u64,
    blinding: *const u8,
    commitment_out: *mut u8,
) -> i32 {
    if secret.is_null() || blinding.is_null() || commitment_out.is_null() {
        return -1;
    }

    let secret_slice = unsafe { slice::from_raw_parts(secret, 32) };
    let blinding_slice = unsafe { slice::from_raw_parts(blinding, 32) };

    let secret_h256 = H256::from_slice(secret_slice);
    let blinding_h256 = H256::from_slice(blinding_slice);

    // Compute commitment using Poseidon hash: H(secret || amount || blinding)
    let commitment = crate::api::compute_commitment(secret_h256, U256::from(amount), blinding_h256)
        .unwrap_or_else(|_| H256::zero());

    unsafe {
        ptr::copy_nonoverlapping(commitment.as_ptr(), commitment_out, 32);
    }

    0
}

/// Compute nullifier
///
/// # Arguments
/// * `secret` - 32-byte secret
/// * `leaf_index` - Merkle tree leaf index
/// * `nullifier_out` - Output buffer for 32-byte nullifier
///
/// # Returns
/// * 0 on success, -1 on failure
#[no_mangle]
pub extern "C" fn compute_nullifier(
    secret: *const u8,
    leaf_index: u32,
    nullifier_out: *mut u8,
) -> i32 {
    if secret.is_null() || nullifier_out.is_null() {
        return -1;
    }

    let secret_slice = unsafe { slice::from_raw_parts(secret, 32) };
    let secret_h256 = H256::from_slice(secret_slice);

    // Compute nullifier using Poseidon hash: H(secret || leaf_index)
    let nullifier = crate::api::compute_nullifier(secret_h256, leaf_index)
        .unwrap_or_else(|_| H256::zero());

    unsafe {
        ptr::copy_nonoverlapping(nullifier.as_ptr(), nullifier_out, 32);
    }

    0
}

/// Poseidon hash of two field elements
///
/// # Arguments
/// * `left` - 32-byte left input
/// * `right` - 32-byte right input
/// * `output` - Output buffer for 32-byte hash result
///
/// # Returns
/// * 0 on success, -1 on failure
#[no_mangle]
pub extern "C" fn poseidon_hash_two(
    left: *const u8,
    right: *const u8,
    output: *mut u8,
) -> i32 {
    if left.is_null() || right.is_null() || output.is_null() {
        return -1;
    }

    let left_slice = unsafe { slice::from_raw_parts(left, 32) };
    let right_slice = unsafe { slice::from_raw_parts(right, 32) };

    let left_h256 = H256::from_slice(left_slice);
    let right_h256 = H256::from_slice(right_slice);

    // Use the Poseidon hash function from crypto module
    let result = crate::crypto::poseidon::poseidon_hash(left_h256, right_h256);

    unsafe {
        ptr::copy_nonoverlapping(result.as_ptr(), output, 32);
    }

    0
}

/// Prove transfer - generates ZK proof
///
/// # Arguments
/// * `handle` - Privacy system handle
/// * `secret` - 32-byte secret
/// * `amount` - Amount as u64
/// * `blinding` - 32-byte blinding factor
/// * `leaf_index` - Merkle tree leaf index
/// * `proof_out` - Output buffer for proof bytes
/// * `proof_len_out` - Output for proof length
/// * `max_proof_len` - Maximum proof buffer size
///
/// # Returns
/// * 0 on success, -1 on failure
#[no_mangle]
pub extern "C" fn prove_transfer(
    handle: *mut std::os::raw::c_void,
    secret: *const u8,
    amount: u64,
    blinding: *const u8,
    leaf_index: u32,
    proof_out: *mut u8,
    proof_len_out: *mut usize,
    max_proof_len: usize,
) -> i32 {
    if handle.is_null() || secret.is_null() || blinding.is_null() || proof_out.is_null() || proof_len_out.is_null() {
        return -1;
    }

    // Validate handle
    let wrapper = unsafe {
        let wrapper_ptr = handle as *mut PrivacySystemHandleWrapper;
        match validate_handle_wrapper(wrapper_ptr as *const _) {
            Some(w) => w,
            None => return -1,
        }
    };

    let secret_slice = unsafe { slice::from_raw_parts(secret, 32) };
    let blinding_slice = unsafe { slice::from_raw_parts(blinding, 32) };

    let secret_h256 = H256::from_slice(secret_slice);
    let blinding_h256 = H256::from_slice(blinding_slice);

    // Generate proof
    match wrapper.handle.proof_system.prove(secret_h256, U256::from(amount), blinding_h256, leaf_index) {
        Ok((proof_bytes, _commitment, _nullifier)) => {
            if proof_bytes.len() > max_proof_len {
                eprintln!("Proof size {} exceeds max buffer size {}", proof_bytes.len(), max_proof_len);
                return -1;
            }

            unsafe {
                ptr::copy_nonoverlapping(proof_bytes.as_ptr(), proof_out, proof_bytes.len());
                *proof_len_out = proof_bytes.len();
            }

            0
        }
        Err(e) => {
            eprintln!("Failed to generate proof: {}", e);
            -1
        }
    }
}

/// Cleanup privacy system
#[no_mangle]
pub extern "C" fn privacy_system_free(handle: *mut std::os::raw::c_void) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle as *mut PrivacySystemHandleWrapper);
        }
    }
}

/// Verify a ZK-SNARK proof for a private transfer
///
/// # Arguments
/// * `handle` - Privacy system handle from `privacy_system_new`
/// * `proof` - Proof bytes to verify
/// * `proof_len` - Length of proof in bytes
/// * `commitment` - 32-byte commitment hash
/// * `nullifier` - 32-byte nullifier hash
///
/// # Returns
/// * `0` - Proof is valid
/// * `1` - Proof is invalid
/// * `-1` - Error (invalid handle, null pointers, conversion error)
///
/// # Safety
/// This function validates all inputs before dereferencing pointers.
/// The proof_bytes slice is valid for the duration of the call.
#[no_mangle]
pub extern "C" fn verify_transfer(
    handle: *mut std::os::raw::c_void,
    proof: *const u8,
    proof_len: usize,
    commitment: *const u8,
    nullifier: *const u8,
) -> i32 {
    // Validate handle
    if handle.is_null() {
        eprintln!("❌ FFI verify_transfer: null handle");
        return -1;
    }

    // Validate proof pointer and length
    if proof.is_null() || proof_len == 0 {
        eprintln!("❌ FFI verify_transfer: invalid proof (null or zero length)");
        return -1;
    }

    // Validate commitment and nullifier pointers
    if commitment.is_null() || nullifier.is_null() {
        eprintln!("❌ FFI verify_transfer: null commitment or nullifier");
        return -1;
    }

    // FIXED: Use validate_handle_wrapper instead of wrapper.validate()
    let wrapper = unsafe {
        let wrapper_ptr = handle as *const PrivacySystemHandleWrapper;
        match validate_handle_wrapper(wrapper_ptr) {
            Some(w) => w,
            None => {
                eprintln!("❌ FFI verify_transfer: invalid handle");
                return -1;
            }
        }
    };

    unsafe {
        // Convert proof bytes to slice
        let proof_bytes = std::slice::from_raw_parts(proof, proof_len);

        // Convert commitment and nullifier to H256
        let commitment_bytes = std::slice::from_raw_parts(commitment, 32);
        let nullifier_bytes = std::slice::from_raw_parts(nullifier, 32);

        // FIXED: H256::from_slice returns H256 directly, not Result
        let commitment_h256 = H256::from_slice(commitment_bytes);
        let nullifier_h256 = H256::from_slice(nullifier_bytes);

        // Call verification method
        match wrapper.handle.proof_system.verify(
            proof_bytes,
            commitment_h256,
            nullifier_h256,
        ) {
            Ok(true) => {
                // Proof is valid
                0
            }
            Ok(false) => {
                // Proof is invalid (shouldn't happen - verify returns error on failure)
                eprintln!("⚠️  FFI verify_transfer: proof verification returned false");
                1
            }
            Err(e) => {
                // Verification error
                eprintln!("❌ FFI verify_transfer: verification failed: {}", e);
                1
            }
        }
    }
}

// Helper function for allocating bytes (used by other FFI modules)
pub(crate) fn allocate_bytes(data: &[u8]) -> *mut u8 {
    let mut vec = data.to_vec();
    let ptr = vec.as_mut_ptr();
    std::mem::forget(vec);
    ptr
}
