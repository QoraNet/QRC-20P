//! FFI bindings for amount splitting and mixing

use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

use super::amount_splitter::{AmountSplitter, AmountMixer};
use super::ffi::{validate_handle_wrapper, PrivacySystemHandleWrapper, FFI_RUNTIME};
use ethereum_types::{Address, U256};

/// Split amount into privacy-preserving chunks
///
/// # Arguments
/// * `handle` - Privacy system handle
/// * `amount_hex` - Amount to split (hex-encoded U256)
/// * `chunks_out` - Output buffer for chunks (each 32 bytes, max 16 chunks)
/// * `chunks_count_out` - Output: number of chunks generated
///
/// # Returns
/// 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn privacy_split_amount(
    handle: *const PrivacySystemHandleWrapper,
    amount_hex: *const c_char,
    chunks_out: *mut u8,
    chunks_count_out: *mut usize,
) -> i32 {
    eprintln!("🔍 privacy_split_amount called");

    let _wrapper = match unsafe { validate_handle_wrapper(handle) } {
        Some(w) => w,
        None => {
            eprintln!("❌ Invalid handle");
            return -1;
        }
    };
    eprintln!("✅ Handle validated");

    let amount_str = match unsafe { CStr::from_ptr(amount_hex).to_str() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to parse amount string: {:?}", e);
            return -1;
        }
    };
    eprintln!("✅ Amount string: {}", amount_str);

    // Parse amount
    let amount = match U256::from_str_radix(amount_str.trim_start_matches("0x"), 16) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("❌ Failed to parse amount hex: {:?}", e);
            return -1;
        }
    };
    eprintln!("✅ Amount parsed: {}", amount);

    // Split amount
    let splitter = AmountSplitter::new();
    let chunks = match splitter.split_for_privacy(amount) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Failed to split amount: {:?}", e);
            return -1;
        }
    };
    eprintln!("✅ Split into {} chunks", chunks.len());

    if chunks.len() > 32 {
        eprintln!("❌ Too many chunks: {} (max 32)", chunks.len());
        return -1; // Too many chunks
    }

    // Copy chunks (each is 32 bytes)
    for (i, chunk) in chunks.iter().enumerate() {
        let mut chunk_bytes = [0u8; 32];
        chunk.to_big_endian(&mut chunk_bytes);

        unsafe {
            ptr::copy_nonoverlapping(
                chunk_bytes.as_ptr(),
                chunks_out.add(i * 32),
                32
            );
        }
    }

    unsafe {
        *chunks_count_out = chunks.len();
    }

    0
}

/// Mix amounts from multiple users asynchronously
///
/// # Arguments
/// * `handle` - Privacy system handle
/// * `user_addresses` - Array of user addresses (20 bytes each)
/// * `user_amounts` - Array of amounts (32 bytes each, hex U256)
/// * `user_count` - Number of users
/// * `mixed_chunks_out` - Output buffer for mixed chunks (20 + 32 bytes per chunk, max 160 chunks)
/// * `mixed_count_out` - Output: number of mixed chunks
///
/// # Returns
/// 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn privacy_mix_amounts(
    handle: *const PrivacySystemHandleWrapper,
    user_addresses: *const u8,
    user_amounts: *const u8,
    user_count: usize,
    mixed_chunks_out: *mut u8,
    mixed_count_out: *mut usize,
) -> i32 {
    let _wrapper = match unsafe { validate_handle_wrapper(handle) } {
        Some(w) => w,
        None => return -1,
    };

    if user_count == 0 || user_count > 16 {
        return -1;
    }

    // Parse inputs
    let mut entries = Vec::new();
    for i in 0..user_count {
        // Parse address (20 bytes)
        let addr_bytes = unsafe { slice::from_raw_parts(user_addresses.add(i * 20), 20) };
        let addr = Address::from_slice(addr_bytes);

        // Parse amount (32 bytes)
        let amount_bytes = unsafe { slice::from_raw_parts(user_amounts.add(i * 32), 32) };
        let amount = U256::from_big_endian(amount_bytes);

        entries.push((addr, amount));
    }

    // Mix amounts using the global runtime
    let mixer = AmountMixer::new();
    let mixed = match FFI_RUNTIME.block_on(mixer.mix_amounts(entries)) {
        Ok(m) => m,
        Err(_) => return -1,
    };

    if mixed.len() > 160 {
        return -1; // Too many chunks
    }

    // Copy mixed chunks (address + amount = 20 + 32 = 52 bytes each)
    for (i, (addr, amount)) in mixed.iter().enumerate() {
        let offset = i * 52;

        // Copy address (20 bytes)
        unsafe {
            ptr::copy_nonoverlapping(
                addr.as_bytes().as_ptr(),
                mixed_chunks_out.add(offset),
                20
            );
        }

        // Copy amount (32 bytes)
        let mut amount_bytes = [0u8; 32];
        amount.to_big_endian(&mut amount_bytes);
        unsafe {
            ptr::copy_nonoverlapping(
                amount_bytes.as_ptr(),
                mixed_chunks_out.add(offset + 20),
                32
            );
        }
    }

    unsafe {
        *mixed_count_out = mixed.len();
    }

    0
}

/// Process chunks with delays asynchronously (returns immediately)
///
/// # Arguments
/// * `handle` - Privacy system handle
/// * `chunks` - Array of chunks (52 bytes each: 20 addr + 32 amount)
/// * `chunk_count` - Number of chunks
/// * `min_delay_ms` - Minimum delay in milliseconds
/// * `max_delay_ms` - Maximum delay in milliseconds
///
/// # Returns
/// 0 on success (chunks scheduled), -1 on error
///
/// Note: This function returns immediately. Chunks are processed in background.
#[no_mangle]
pub extern "C" fn privacy_process_chunks_with_delay(
    handle: *const PrivacySystemHandleWrapper,
    chunks: *const u8,
    chunk_count: usize,
    min_delay_ms: u64,
    max_delay_ms: u64,
) -> i32 {
    let _wrapper = match unsafe { validate_handle_wrapper(handle) } {
        Some(w) => w,
        None => return -1,
    };

    if chunk_count == 0 || chunk_count > 160 {
        return -1;
    }

    // Parse chunks
    let mut chunk_vec = Vec::new();
    for i in 0..chunk_count {
        let offset = i * 52;

        // Parse address
        let addr_bytes = unsafe { slice::from_raw_parts(chunks.add(offset), 20) };
        let addr = Address::from_slice(addr_bytes);

        // Parse amount
        let amount_bytes = unsafe { slice::from_raw_parts(chunks.add(offset + 20), 32) };
        let amount = U256::from_big_endian(amount_bytes);

        chunk_vec.push((addr, amount));
    }

    // Spawn background task for processing chunks with delays
    let mixer = AmountMixer::new();
    tokio::spawn(async move {
        let handles = mixer.process_chunks_async(
            chunk_vec,
            (min_delay_ms, max_delay_ms)
        ).await;

        // Wait for all chunks to complete
        for handle in handles {
            let _ = handle.await;
        }
    });

    0
}
