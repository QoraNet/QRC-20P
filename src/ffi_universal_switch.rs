//! FFI exports for Universal Switch
//! For Go integration with L1 blockchain

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Arc;
use ethereum_types::{Address, H256, U256};
use serde_json;
use once_cell::sync::Lazy;

use super::universal_switch::{UniversalSwitch, SwitchConfig};
use super::common_types::TokenId;
use super::halo2_circuits::ProductionProofSystem;

/// Single shared runtime for all FFI operations - MUST be initialized FIRST
static FFI_RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("ffi-runtime")
        .enable_all()
        .build()
        .expect("Failed to create FFI runtime")
});

/// Global proof system for ZK verification
static GLOBAL_PROOF_SYSTEM: Lazy<Arc<ProductionProofSystem>> = Lazy::new(|| {
    match ProductionProofSystem::new(17, 8) {
        Ok(ps) => Arc::new(ps),
        Err(e) => {
            panic!("Failed to initialize global proof system: {}", e);
        }
    }
});

/// Global Universal Switch instance (created once with runtime context)
static GLOBAL_SWITCH: Lazy<Arc<UniversalSwitch>> = Lazy::new(|| {
    let _guard = FFI_RUNTIME.enter();
    UniversalSwitch::new(SwitchConfig::default(), GLOBAL_PROOF_SYSTEM.clone())
});

/// Safe C string creation - handles null bytes gracefully
fn safe_c_string(s: String) -> *const c_char {
    let sanitized = s.replace('\0', "");
    CString::new(sanitized)
        .unwrap_or_else(|_| CString::new("Error").unwrap())
        .into_raw()
}

/// FFI Result structure for Go integration
#[repr(C)]
pub struct SwitchResult {
    pub success: u8,
    pub request_id: [u8; 32],
    pub error_msg: *const c_char,
}

/// FFI handle for Universal Switch
pub struct UniversalSwitchHandle {
    switch: Arc<UniversalSwitch>,
}

/// BLOCKING: This function blocks until the operation completes.
/// Do not call from performance-critical Go code.
#[no_mangle]
pub extern "C" fn universal_switch_process(
    token_id: *const c_char,
    from_addr: *const c_char,
    to_mode: u8,  // 0=public, 1=private
    amount: *const c_char,
) -> SwitchResult {
    // Parse token ID
    let token_id_str = unsafe {
        match CStr::from_ptr(token_id).to_str() {
            Ok(s) => s,
            Err(e) => return SwitchResult {
                success: 0,
                request_id: [0; 32],
                error_msg: safe_c_string(format!("Invalid token_id: {}", e)),
            }
        }
    };

    // Parse from address
    let from_str = unsafe {
        match CStr::from_ptr(from_addr).to_str() {
            Ok(s) => s,
            Err(e) => return SwitchResult {
                success: 0,
                request_id: [0; 32],
                error_msg: safe_c_string(format!("Invalid address: {}", e)),
            }
        }
    };

    // Parse amount
    let amount_str = unsafe {
        match CStr::from_ptr(amount).to_str() {
            Ok(s) => s,
            Err(e) => return SwitchResult {
                success: 0,
                request_id: [0; 32],
                error_msg: safe_c_string(format!("Invalid amount: {}", e)),
            }
        }
    };

    // Convert to proper types
    let token = match parse_h256(token_id_str) {
        Some(h) => TokenId(h),
        None => return SwitchResult {
            success: 0,
            request_id: [0; 32],
            error_msg: safe_c_string("Failed to parse token ID".to_string()),
        }
    };

    let addr = match parse_address(from_str) {
        Some(a) => a,
        None => return SwitchResult {
            success: 0,
            request_id: [0; 32],
            error_msg: safe_c_string("Failed to parse address".to_string()),
        }
    };

    let amt = match amount_str.parse::<u128>() {
        Ok(a) => U256::from(a),
        Err(_) => return SwitchResult {
            success: 0,
            request_id: [0; 32],
            error_msg: safe_c_string("Failed to parse amount".to_string()),
        }
    };

    // Generate request ID
    let request_id = H256::random();
    let mut request_id_bytes = [0u8; 32];
    request_id_bytes.copy_from_slice(request_id.as_bytes());

    // Use global switch instance (no memory leak)
    let result = FFI_RUNTIME.block_on(async {
        match to_mode {
            1 => {
                // Switch to private
                GLOBAL_SWITCH.switch_to_private_with_splitting(
                    token,
                    addr,
                    amt,
                    H256::random(),
                    H256::random()
                ).await
            },
            0 => {
                // ✅ PRODUCTION: Switch to public requires ZK proof and nullifier
                //
                // This endpoint (universal_switch_mode) is simplified for private switches only.
                //
                // For public (unshield) operations, use the dedicated endpoint:
                // `universal_switch_unshield(token, user, amount, proof_bytes, nullifier_bytes)`
                //
                // Required parameters for unshield:
                // - proof_bytes: ZK proof proving ownership of commitment
                // - nullifier: Unique value preventing double-spending
                //
                // The proof must verify:
                // 1. User knows secret for commitment in Merkle tree
                // 2. Amount matches committed amount
                // 3. Nullifier hasn't been used before
                //
                // Cannot implement here because:
                // - Generating proof requires private key (not available to FFI)
                // - Proof generation is async and computationally expensive
                // - Go layer should handle proof generation with user's key

                Err(anyhow::anyhow!(
                    "Public switch (unshield) not supported in this endpoint. \
                    Use dedicated unshield endpoint with ZK proof and nullifier. \
                    Proof generation must happen Go-side with user's private key."
                ))
            },
            _ => {
                Err(anyhow::anyhow!("Invalid mode: {}", to_mode))
            }
        }
    });

    match result {
        Ok(_) => SwitchResult {
            success: 1,
            request_id: request_id_bytes,
            error_msg: std::ptr::null(),
        },
        Err(e) => SwitchResult {
            success: 0,
            request_id: request_id_bytes,
            error_msg: safe_c_string(format!("Switch failed: {}", e)),
        }
    }
}

/// Initialize Universal Switch handle
///
/// NOTE: This returns a handle to the GLOBAL switch instance.
/// Custom config is ignored to prevent memory leaks.
/// The global switch uses SwitchConfig::default().
#[no_mangle]
pub extern "C" fn universal_switch_init(
    _config_json: *const c_char,
) -> *mut UniversalSwitchHandle {
    // Use global switch instance (prevents task leaks)
    // Custom config is intentionally ignored
    Box::into_raw(Box::new(UniversalSwitchHandle {
        switch: Arc::clone(&GLOBAL_SWITCH)
    }))
}

/// Switch to private mode with optional splitting
#[no_mangle]
pub extern "C" fn switch_to_private_ffi(
    handle: *mut UniversalSwitchHandle,
    token_id_hex: *const c_char,
    user_hex: *const c_char,
    amount_str: *const c_char,
    use_splitting: u8,
) -> *const c_char {
    if handle.is_null() {
        return safe_c_string(r#"{"error": "null handle"}"#.to_string());
    }

    let handle = unsafe { &*handle };

    // Parse token ID
    let token_id_str = unsafe { CStr::from_ptr(token_id_hex).to_str().unwrap_or("") };
    let token_id = match parse_h256(token_id_str) {
        Some(h) => TokenId(h),
        None => return safe_c_string(r#"{"error": "invalid token_id"}"#.to_string()),
    };

    // Parse user address
    let user_str = unsafe { CStr::from_ptr(user_hex).to_str().unwrap_or("") };
    let user = match parse_address(user_str) {
        Some(addr) => addr,
        None => return safe_c_string(r#"{"error": "invalid user address"}"#.to_string()),
    };

    // Parse amount
    let amount_s = unsafe { CStr::from_ptr(amount_str).to_str().unwrap_or("0") };
    let amount = match amount_s.parse::<u128>() {
        Ok(a) => U256::from(a),
        Err(_) => return safe_c_string(r#"{"error": "invalid amount"}"#.to_string()),
    };

    // Use global FFI runtime
    let result = FFI_RUNTIME.block_on(async {
        if use_splitting == 1 {
            handle.switch.switch_to_private_with_splitting(
                token_id, user, amount, H256::random(), H256::random()
            ).await
        } else {
            handle.switch.switch_to_private(
                token_id, user, amount, H256::random(), H256::random()
            ).await.map(|h| vec![h])
        }
    });

    match result {
        Ok(hashes) => {
            let hashes_hex: Vec<String> = hashes.iter()
                .map(|h| format!("0x{}", hex::encode(h.as_bytes())))
                .collect();
            let json = serde_json::json!({
                "commitments": hashes_hex,
                "count": hashes_hex.len()
            });
            safe_c_string(json.to_string())
        }
        Err(e) => {
            let error = format!(r#"{{"error": "{}"}}"#, e);
            safe_c_string(error)
        }
    }
}

/// Verify switch request for consensus
#[no_mangle]
pub extern "C" fn verify_switch_for_consensus(
    handle: *mut UniversalSwitchHandle,
    request_json: *const c_char,
    block_height: u64,
    state_root_hex: *const c_char,
) -> u8 {
    if handle.is_null() {
        return 0;
    }

    let handle = unsafe { &*handle };

    // Parse request
    let request_str = unsafe { CStr::from_ptr(request_json).to_str().unwrap_or("") };
    let request = match serde_json::from_str(request_str) {
        Ok(r) => r,
        Err(_) => return 0,
    };

    // Parse state root
    let state_root_str = unsafe { CStr::from_ptr(state_root_hex).to_str().unwrap_or("") };
    let state_root = match parse_h256(state_root_str) {
        Some(h) => h,
        None => return 0,
    };

    // Use global FFI runtime
    let result = FFI_RUNTIME.block_on(async {
        handle.switch.verify_switch_for_consensus(&request, block_height, state_root).await
    });

    match result {
        Ok(valid) => if valid { 1 } else { 0 },
        Err(_) => 0,
    }
}

/// Get unified balance
#[no_mangle]
pub extern "C" fn get_unified_balance(
    handle: *mut UniversalSwitchHandle,
    token_id_hex: *const c_char,
    user_hex: *const c_char,
) -> *const c_char {
    if handle.is_null() {
        return safe_c_string("0".to_string());
    }

    let handle = unsafe { &*handle };

    // Parse token ID
    let token_id_str = unsafe { CStr::from_ptr(token_id_hex).to_str().unwrap_or("") };
    let token_id = match parse_h256(token_id_str) {
        Some(h) => TokenId(h),
        None => return safe_c_string("0".to_string()),
    };

    // Parse user address
    let user_str = unsafe { CStr::from_ptr(user_hex).to_str().unwrap_or("") };
    let user = match parse_address(user_str) {
        Some(addr) => addr,
        None => return safe_c_string("0".to_string()),
    };

    // Use global FFI runtime
    let balance = FFI_RUNTIME.block_on(async {
        handle.switch.get_unified_balance(token_id, user).await
    });

    safe_c_string(balance.to_string())
}

/// Register token pair
#[no_mangle]
pub extern "C" fn register_token_pair(
    handle: *mut UniversalSwitchHandle,
    public_address_hex: *const c_char,
    private_address_hex: *const c_char,
    name: *const c_char,
    symbol: *const c_char,
    decimals: u8,
    total_supply_str: *const c_char,
) -> *const c_char {
    if handle.is_null() {
        return safe_c_string(r#"{"error": "null handle"}"#.to_string());
    }

    let handle = unsafe { &*handle };

    // Parse addresses
    let public_str = unsafe { CStr::from_ptr(public_address_hex).to_str().unwrap_or("") };
    let public_address = match parse_address(public_str) {
        Some(addr) => addr,
        None => return safe_c_string(r#"{"error": "invalid public address"}"#.to_string()),
    };

    let private_str = unsafe { CStr::from_ptr(private_address_hex).to_str().unwrap_or("") };
    let private_address = match parse_address(private_str) {
        Some(addr) => addr,
        None => return safe_c_string(r#"{"error": "invalid private address"}"#.to_string()),
    };

    // Parse name and symbol
    let name_str = unsafe { CStr::from_ptr(name).to_str().unwrap_or("Unknown") };
    let symbol_str = unsafe { CStr::from_ptr(symbol).to_str().unwrap_or("UNK") };

    // Parse total supply
    let supply_str = unsafe { CStr::from_ptr(total_supply_str).to_str().unwrap_or("0") };
    let total_supply = match supply_str.parse::<u128>() {
        Ok(s) => U256::from(s),
        Err(_) => U256::zero(),
    };

    // Use global FFI runtime
    let result = FFI_RUNTIME.block_on(async {
        handle.switch.register_token_pair(
            public_address,
            private_address,
            name_str.to_string(),
            symbol_str.to_string(),
            decimals,
            total_supply,
        ).await
    });

    match result {
        Ok(token_id) => {
            let json = format!(r#"{{"token_id": "0x{}"}}"#, hex::encode(token_id.0.as_bytes()));
            safe_c_string(json)
        }
        Err(e) => {
            let error = format!(r#"{{"error": "{}"}}"#, e);
            safe_c_string(error)
        }
    }
}

/// Commit delayed switch (1-24 hour delay)
#[no_mangle]
pub extern "C" fn commit_switch_to_private_ffi(
    handle: *mut UniversalSwitchHandle,
    token_id_hex: *const c_char,
    user_hex: *const c_char,
    amount_str: *const c_char,
    delay_seconds: u64,  // 3600-86400
) -> *const c_char {
    if handle.is_null() {
        return safe_c_string(r#"{"error": "null handle"}"#.to_string());
    }

    let handle = unsafe { &*handle };

    // Parse parameters (same as existing functions)
    let token_id = match parse_token_id(token_id_hex) {
        Some(t) => t,
        None => return safe_c_string(r#"{"error": "invalid token_id"}"#.to_string()),
    };

    let user = match parse_user(user_hex) {
        Some(u) => u,
        None => return safe_c_string(r#"{"error": "invalid user"}"#.to_string()),
    };

    let amount = match parse_amount(amount_str) {
        Some(a) => a,
        None => return safe_c_string(r#"{"error": "invalid amount"}"#.to_string()),
    };

    let result = FFI_RUNTIME.block_on(async {
        handle.switch.commit_switch_to_private(
            token_id,
            user,
            amount,
            H256::random(),
            H256::random(),
            delay_seconds,
        ).await
    });

    match result {
        Ok(request_id) => {
            let json = serde_json::json!({
                "request_id": format!("0x{}", hex::encode(request_id.as_bytes())),
                "execute_after_seconds": delay_seconds
            });
            safe_c_string(json.to_string())
        }
        Err(e) => safe_c_string(format!(r#"{{"error": "{}"}}"#, e)),
    }
}

/// Execute delayed switch after delay period
#[no_mangle]
pub extern "C" fn execute_delayed_switch_ffi(
    handle: *mut UniversalSwitchHandle,
    request_id_hex: *const c_char,
) -> u8 {
    if handle.is_null() {
        return 0;
    }

    let handle = unsafe { &*handle };

    let request_id_str = unsafe { CStr::from_ptr(request_id_hex).to_str().unwrap_or("") };
    let request_id = match parse_h256(request_id_str) {
        Some(h) => h,
        None => return 0,
    };

    let result = FFI_RUNTIME.block_on(async {
        handle.switch.execute_delayed_switch(request_id).await
    });

    match result {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

/// Commit batch switch (3-100 users)
#[no_mangle]
pub extern "C" fn commit_batch_switch_ffi(
    handle: *mut UniversalSwitchHandle,
    token_id_hex: *const c_char,
    entries_json: *const c_char,  // JSON array of {user, amount, secret, nonce}
    delay_seconds: u64,
) -> *const c_char {
    if handle.is_null() {
        return safe_c_string(r#"{"error": "null handle"}"#.to_string());
    }

    let handle = unsafe { &*handle };

    let token_id = match parse_token_id(token_id_hex) {
        Some(t) => t,
        None => return safe_c_string(r#"{"error": "invalid token_id"}"#.to_string()),
    };

    // Parse entries JSON
    let entries_str = unsafe { CStr::from_ptr(entries_json).to_str().unwrap_or("[]") };
    let entries: Vec<BatchEntry> = match serde_json::from_str(entries_str) {
        Ok(e) => e,
        Err(_) => return safe_c_string(r#"{"error": "invalid entries JSON"}"#.to_string()),
    };

    // Convert to internal format
    let internal_entries: Vec<_> = entries.iter()
        .filter_map(|e| {
            let user = parse_address(&e.user)?;
            let amount = e.amount.parse::<u128>().ok().map(U256::from)?;
            let secret = parse_h256(&e.secret)?;
            let nonce = parse_h256(&e.nonce)?;
            Some((user, amount, secret, nonce))
        })
        .collect();

    let result = FFI_RUNTIME.block_on(async {
        handle.switch.commit_batch_switch(token_id, internal_entries, delay_seconds).await
    });

    match result {
        Ok(batch_id) => {
            let json = serde_json::json!({
                "batch_id": format!("0x{}", hex::encode(batch_id.as_bytes()))
            });
            safe_c_string(json.to_string())
        }
        Err(e) => safe_c_string(format!(r#"{{"error": "{}"}}"#, e)),
    }
}

/// Cleanup handle
#[no_mangle]
pub extern "C" fn universal_switch_cleanup(handle: *mut UniversalSwitchHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle);
        }
    }
}

/// Free string returned by FFI functions
#[no_mangle]
pub extern "C" fn free_ffi_string(s: *const c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s as *mut c_char);
        }
    }
}

// Helper functions
fn parse_h256(s: &str) -> Option<H256> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    Some(H256::from_slice(&bytes))
}

fn parse_address(s: &str) -> Option<Address> {
    let s = s.trim_start_matches("0x");
    if s.len() != 40 {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    Some(Address::from_slice(&bytes))
}

fn parse_token_id(token_id_hex: *const c_char) -> Option<TokenId> {
    let token_id_str = unsafe { CStr::from_ptr(token_id_hex).to_str().ok()? };
    Some(TokenId(parse_h256(token_id_str)?))
}

fn parse_user(user_hex: *const c_char) -> Option<Address> {
    let user_str = unsafe { CStr::from_ptr(user_hex).to_str().ok()? };
    parse_address(user_str)
}

fn parse_amount(amount_str: *const c_char) -> Option<U256> {
    let amount_s = unsafe { CStr::from_ptr(amount_str).to_str().ok()? };
    amount_s.parse::<u128>().ok().map(U256::from)
}

#[derive(serde::Deserialize)]
struct BatchEntry {
    user: String,
    amount: String,
    secret: String,
    nonce: String,
}