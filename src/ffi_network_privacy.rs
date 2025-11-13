//! FFI bindings for network privacy layer (Dandelion++, batching, Tor/I2P)

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::slice;

use super::ffi::{validate_handle_wrapper, PrivacySystemHandleWrapper, FFI_RUNTIME};
use ethereum_types::H256;

/// Configure network privacy settings
///
/// # Arguments
/// * `handle` - Privacy system handle
/// * `enable_dandelion` - Enable Dandelion++ protocol
/// * `enable_batching` - Enable transaction batching
/// * `enable_tor` - Enable Tor routing
/// * `batch_window_ms` - Batching time window (milliseconds)
/// * `min_batch_size` - Minimum batch size
///
/// # Returns
/// -2 (NOT SUPPORTED in production)
///
/// # PRODUCTION NOTE
/// Network privacy configuration is immutable after initialization.
/// To change network privacy settings, you must:
/// 1. Destroy the current privacy handle with privacy_system_destroy()
/// 2. Create a new NetworkPrivacyConfig with desired settings
/// 3. Create a new privacy handle with privacy_system_new()
///
/// This design prevents race conditions and ensures all privacy components
/// use consistent configuration.
#[no_mangle]
pub extern "C" fn privacy_configure_network(
    handle: *const PrivacySystemHandleWrapper,
    enable_dandelion: bool,
    enable_batching: bool,
    enable_tor: bool,
    batch_window_ms: u64,
    min_batch_size: usize,
) -> i32 {
    let _wrapper = match unsafe { validate_handle_wrapper(handle) } {
        Some(w) => w,
        None => return -1,
    };

    tracing::error!(
        "privacy_configure_network is not supported in production. \
         Network config is immutable after initialization. \
         Requested: dandelion={}, batching={}, tor={}, window={}ms, min_batch={}. \
         To change config, destroy handle and create new one with desired config.",
        enable_dandelion, enable_batching, enable_tor, batch_window_ms, min_batch_size
    );

    -2 // Return -2 to indicate "not supported" (vs -1 for "error")
}

/// Send private transaction with full network privacy
///
/// # Arguments
/// * `handle` - Privacy system handle
/// * `tx_data` - Transaction data
/// * `tx_data_len` - Length of transaction data
/// * `tx_hash` - Transaction hash (32 bytes)
///
/// # Returns
/// 0 on success, -1 on error
///
/// Features used:
/// - Dandelion++ (hides origin IP)
/// - Transaction batching (breaks timing correlation)
/// - Tor/I2P routing (if enabled)
/// - Traffic padding
/// - Decoy traffic
#[no_mangle]
pub extern "C" fn privacy_send_private_transaction(
    handle: *const PrivacySystemHandleWrapper,
    tx_data: *const u8,
    tx_data_len: usize,
    tx_hash: *const u8,
) -> i32 {
    let wrapper = match unsafe { validate_handle_wrapper(handle) } {
        Some(w) => w,
        None => return -1,
    };

    if tx_data.is_null() || tx_hash.is_null() || tx_data_len == 0 {
        return -1;
    }

    // Parse transaction data
    let data = unsafe { slice::from_raw_parts(tx_data, tx_data_len) };

    // Parse transaction hash
    let hash_bytes = unsafe { slice::from_raw_parts(tx_hash, 32) };
    let hash = H256::from_slice(hash_bytes);

    // Send with full privacy protections
    let network_privacy = wrapper.handle.network_privacy.clone();
    match FFI_RUNTIME.block_on(async move {
        network_privacy.send_private_transaction(data, hash, None).await
    }) {
        Ok(_) => 0,
        Err(e) => {
            tracing::error!("Failed to send private transaction: {}", e);
            -1
        }
    }
}

/// Decorrelate amount (add noise and split)
///
/// # Arguments
/// * `handle` - Privacy system handle
/// * `amount_hex` - Amount to decorrelate (hex-encoded U256)
/// * `chunks_out` - Output buffer for chunks (each 32 bytes, max 16 chunks)
/// * `chunks_count_out` - Output: number of chunks generated
///
/// # Returns
/// 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn privacy_decorrelate_amount(
    handle: *const PrivacySystemHandleWrapper,
    amount_hex: *const c_char,
    chunks_out: *mut u8,
    chunks_count_out: *mut usize,
) -> i32 {
    use ethereum_types::U256;

    let wrapper = match unsafe { validate_handle_wrapper(handle) } {
        Some(w) => w,
        None => return -1,
    };

    let amount_str = match unsafe { CStr::from_ptr(amount_hex).to_str() } {
        Ok(s) => s,
        Err(_) => return -1,
    };

    // Parse amount
    let amount = match U256::from_str_radix(amount_str.trim_start_matches("0x"), 16) {
        Ok(a) => a,
        Err(_) => return -1,
    };

    // Decorrelate amount
    let chunks = wrapper.handle.network_privacy.decorrelate_amount(amount);

    if chunks.len() > 16 {
        return -1;
    }

    // Copy chunks
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

/// Start background Dandelion cleanup task
///
/// # Arguments
/// * `handle` - Privacy system handle
///
/// # Returns
/// 0 on success, -1 on error
///
/// Note: This should be called once during initialization.
/// It runs a background task that cleans up old Dandelion states every 60 seconds.
#[no_mangle]
pub extern "C" fn privacy_start_dandelion_cleanup(
    handle: *const PrivacySystemHandleWrapper,
) -> i32 {
    let wrapper = match unsafe { validate_handle_wrapper(handle) } {
        Some(w) => w,
        None => return -1,
    };

    // Call start_cleanup_task from within FFI_RUNTIME context
    let network_privacy = wrapper.handle.network_privacy.clone();
    FFI_RUNTIME.block_on(async move {
        // Enter runtime context, then spawn the task
        let _guard = tokio::runtime::Handle::current();
        network_privacy.start_cleanup_task();
    });

    tracing::info!("Started Dandelion cleanup background task");

    0
}

/// Get network privacy statistics
///
/// # Arguments
/// * `handle` - Privacy system handle
/// * `stats_out` - Output buffer for stats (JSON string, max 1024 bytes)
///
/// # Returns
/// 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn privacy_get_network_stats(
    handle: *const PrivacySystemHandleWrapper,
    stats_out: *mut c_char,
    stats_len: usize,
) -> i32 {
    let wrapper = match unsafe { validate_handle_wrapper(handle) } {
        Some(w) => w,
        None => return -1,
    };

    // Get actual stats from network_privacy layer
    let stats = wrapper.handle.network_privacy.get_stats();
    let stats_json = match serde_json::to_string(&stats) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let json_len = stats_json.len();
    if json_len >= stats_len {
        return -1;
    }

    let c_stats = match CString::new(stats_json) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    unsafe {
        ptr::copy_nonoverlapping(
            c_stats.as_ptr(),
            stats_out,
            json_len + 1
        );
    }

    0
}
