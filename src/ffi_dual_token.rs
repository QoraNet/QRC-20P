// FFI Implementation for Dual Token Deployment - PRODUCTION
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use ethereum_types::{Address, U256};
use crate::common_types::TokenId;
use crate::ffi::{FFI_RUNTIME, PrivacySystemHandleWrapper, validate_handle_wrapper_mut};
use super::common_types::parse_address;

#[repr(C)]
pub struct DualTokenDeployResult {
    pub token_id: [u8; 32],
    pub public_address: [u8; 20],
    pub private_address: [u8; 20],
    pub success: u8,
    pub error_code: u32,  // NEW: Error codes for debugging
}

/// Deploy a dual-mode token through FFI
#[no_mangle]
pub extern "C" fn deploy_dual_token(
    handle: *mut std::ffi::c_void,
    creator: *const c_char,
    name: *const c_char,
    symbol: *const c_char,
    total_supply: *const c_char,
    decimals: u8,
    block_number: u64,  // NEW: Pass actual block number from Go
) -> *mut DualTokenDeployResult {
    // Validate handle
    let wrapper = unsafe {
        let wrapper_ptr = handle as *mut PrivacySystemHandleWrapper;
        match validate_handle_wrapper_mut(wrapper_ptr) {
            Some(w) => w,
            None => return create_error_result(1), // Error: Invalid handle
        }
    };

    // Parse creator address
    let creator_str = unsafe {
        match CStr::from_ptr(creator).to_str() {
            Ok(s) => s,
            Err(_) => return create_error_result(2), // Error: Invalid creator string
        }
    };

    let creator_addr = match parse_address(creator_str) {
        Some(addr) => addr,
        None => return create_error_result(3), // Error: Invalid creator address
    };

    // Parse token details
    let name_str = unsafe {
        match CStr::from_ptr(name).to_str() {
            Ok(s) => s,
            Err(_) => return create_error_result(4), // Error: Invalid name
        }
    };

    let symbol_str = unsafe {
        match CStr::from_ptr(symbol).to_str() {
            Ok(s) => s,
            Err(_) => return create_error_result(5), // Error: Invalid symbol
        }
    };

    // Validate name and symbol
    if name_str.is_empty() || name_str.len() > 50 {
        return create_error_result(6); // Error: Name length invalid
    }

    if symbol_str.is_empty() || symbol_str.len() > 10 {
        return create_error_result(7); // Error: Symbol length invalid
    }

    // Parse total supply
    let supply_str = unsafe {
        match CStr::from_ptr(total_supply).to_str() {
            Ok(s) => s,
            Err(_) => return create_error_result(8), // Error: Invalid supply string
        }
    };

    let total_supply = match supply_str.parse::<u128>() {
        Ok(val) => {
            if val == 0 {
                return create_error_result(9); // Error: Zero supply
            }
            U256::from(val)
        }
        Err(_) => return create_error_result(10), // Error: Supply parse failed
    };

    // Validate decimals
    if decimals > 18 {
        return create_error_result(11); // Error: Decimals > 18
    }

    // Deploy token using TokenFactory
    eprintln!("[FFI] Starting deploy_dual_token...");

    let result = FFI_RUNTIME.block_on(async {
        eprintln!("[FFI] Inside async block, calling deploy_dual_token...");
        let res = wrapper.handle.token_factory.deploy_dual_token(
            creator_addr,
            name_str.to_string(),
            symbol_str.to_string(),
            total_supply,
            decimals,
            true, // Enable privacy by default
            block_number, // Use actual block number from Go
        ).await;
        eprintln!("[FFI] deploy_dual_token completed with result: {:?}", res.is_ok());
        res
    });

    eprintln!("[FFI] After block_on, result: {:?}", result.is_ok());

    match result {
        Ok((token_id, public_address, private_address)) => {
            // ✅ FIX: Use addresses returned directly from deploy_dual_token_internal()
            // No need to look up metadata since Rust is now stateless
            let mut result = Box::new(DualTokenDeployResult {
                token_id: [0u8; 32],
                public_address: [0u8; 20],
                private_address: [0u8; 20],
                success: 1,
                error_code: 0,
            });

            result.token_id.copy_from_slice(token_id.0.as_bytes());
            result.public_address.copy_from_slice(public_address.as_bytes());
            result.private_address.copy_from_slice(private_address.as_bytes());

            Box::into_raw(result)
        }
        Err(e) => {
            // Log error for debugging
            tracing::error!("Token deployment failed: {:?}", e);
            create_error_result(13) // Error: Deployment failed
        }
    }
}

/// Helper to create error result
fn create_error_result(error_code: u32) -> *mut DualTokenDeployResult {
    let result = Box::new(DualTokenDeployResult {
        token_id: [0u8; 32],
        public_address: [0u8; 20],
        private_address: [0u8; 20],
        success: 0,
        error_code,
    });
    Box::into_raw(result)
}

/// Get token metadata by token ID
#[no_mangle]
pub extern "C" fn get_token_metadata(
    handle: *mut std::ffi::c_void,
    token_id: *const c_char,
) -> *mut TokenMetadataResult {
    let wrapper = unsafe {
        let wrapper_ptr = handle as *mut PrivacySystemHandleWrapper;
        match validate_handle_wrapper_mut(wrapper_ptr) {
            Some(w) => w,
            None => return ptr::null_mut(),
        }
    };

    let token_str = unsafe {
        match CStr::from_ptr(token_id).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    let token_id = match super::common_types::parse_h256(token_str) {
        Some(h) => TokenId(h),
        None => return ptr::null_mut(),
    };

    let result = tokio::task::block_in_place(|| {
        FFI_RUNTIME.block_on(async {
            let factory = &wrapper.handle.token_factory;
            factory.get_token(&token_id).await
        })
    });

    match result {
        Some(metadata) => {
            let name_cstr = CString::new(metadata.name).unwrap_or_default();
            let symbol_cstr = CString::new(metadata.symbol).unwrap_or_default();

            // Convert U256 to string for FFI safety
            let total_supply_str = metadata.total_supply.to_string();
            let supply_cstr = CString::new(total_supply_str).unwrap_or_default();

            let result = Box::new(TokenMetadataResult {
                name: name_cstr.into_raw(),
                symbol: symbol_cstr.into_raw(),
                decimals: metadata.decimals,
                total_supply: supply_cstr.into_raw(), // Changed to string
                public_address: metadata.public_address.to_fixed_bytes(),
                private_address: metadata.private_address.to_fixed_bytes(),
                is_active: if metadata.is_active { 1 } else { 0 },
                created_at_block: metadata.created_at_block,
                success: 1,
            });

            Box::into_raw(result)
        }
        None => ptr::null_mut(),
    }
}

/// Get token metadata by symbol
#[no_mangle]
pub extern "C" fn get_token_by_symbol(
    handle: *mut std::ffi::c_void,
    symbol: *const c_char,
) -> *mut TokenMetadataResult {
    let wrapper = unsafe {
        let wrapper_ptr = handle as *mut PrivacySystemHandleWrapper;
        match validate_handle_wrapper_mut(wrapper_ptr) {
            Some(w) => w,
            None => return ptr::null_mut(),
        }
    };

    let symbol_str = unsafe {
        match CStr::from_ptr(symbol).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    let result = tokio::task::block_in_place(|| {
        FFI_RUNTIME.block_on(async {
            let factory = &wrapper.handle.token_factory;
            factory.get_token_by_symbol(symbol_str).await
        })
    });

    match result {
        Some(metadata) => {
            let name_cstr = CString::new(metadata.name).unwrap_or_default();
            let symbol_cstr = CString::new(metadata.symbol).unwrap_or_default();
            let total_supply_str = metadata.total_supply.to_string();
            let supply_cstr = CString::new(total_supply_str).unwrap_or_default();

            let result = Box::new(TokenMetadataResult {
                name: name_cstr.into_raw(),
                symbol: symbol_cstr.into_raw(),
                decimals: metadata.decimals,
                total_supply: supply_cstr.into_raw(),
                public_address: metadata.public_address.to_fixed_bytes(),
                private_address: metadata.private_address.to_fixed_bytes(),
                is_active: if metadata.is_active { 1 } else { 0 },
                created_at_block: metadata.created_at_block,
                success: 1,
            });

            Box::into_raw(result)
        }
        None => ptr::null_mut(),
    }
}

#[repr(C)]
pub struct TokenMetadataResult {
    pub name: *mut c_char,
    pub symbol: *mut c_char,
    pub decimals: u8,
    pub total_supply: *mut c_char,  // Changed to string for large numbers
    pub public_address: [u8; 20],
    pub private_address: [u8; 20],
    pub is_active: u8,
    pub created_at_block: u64,
    pub success: u8,
}

/// Free dual token result
#[no_mangle]
pub extern "C" fn free_dual_token_result(result: *mut DualTokenDeployResult) {
    if !result.is_null() {
        unsafe {
            let _ = Box::from_raw(result);
        }
    }
}

/// Free token metadata result
#[no_mangle]
pub extern "C" fn free_token_metadata_result(result: *mut TokenMetadataResult) {
    if !result.is_null() {
        unsafe {
            let boxed = Box::from_raw(result);
            if !boxed.name.is_null() {
                let _ = CString::from_raw(boxed.name);
            }
            if !boxed.symbol.is_null() {
                let _ = CString::from_raw(boxed.symbol);
            }
            if !boxed.total_supply.is_null() {
                let _ = CString::from_raw(boxed.total_supply);
            }
        }
    }
}

/// Get standard amounts for privacy (new feature)
#[no_mangle]
pub extern "C" fn get_standard_amounts(
    decimals: u8,
) -> *mut StandardAmountsResult {
    let base = 10u128.pow(decimals as u32);

    let amounts = vec![
        1 * base,
        5 * base,
        10 * base,
        50 * base,
        100 * base,
        500 * base,
        1000 * base,
        5000 * base,
        10000 * base,
    ];

    let mut amount_strings = Vec::new();
    for amount in amounts {
        let s = CString::new(U256::from(amount).to_string()).unwrap_or_default();
        amount_strings.push(s.into_raw());
    }

    let result = Box::new(StandardAmountsResult {
        amounts: amount_strings.as_mut_ptr(),
        count: amount_strings.len(),
    });

    std::mem::forget(amount_strings);

    Box::into_raw(result)
}

#[repr(C)]
pub struct StandardAmountsResult {
    pub amounts: *mut *mut c_char,
    pub count: usize,
}

#[no_mangle]
pub extern "C" fn free_standard_amounts(result: *mut StandardAmountsResult) {
    if !result.is_null() {
        unsafe {
            let boxed = Box::from_raw(result);
            for i in 0..boxed.count {
                let ptr = *boxed.amounts.add(i);
                if !ptr.is_null() {
                    let _ = CString::from_raw(ptr);
                }
            }
        }
    }
}

/// Phase 1: Commit token deployment (anti-frontrunning)
#[no_mangle]
pub extern "C" fn commit_token_deployment_ffi(
    handle: *mut std::ffi::c_void,
    creator: *const c_char,
    symbol: *const c_char,
    block_number: u64,
) -> *mut CommitmentResult {
    let wrapper = unsafe {
        let wrapper_ptr = handle as *mut PrivacySystemHandleWrapper;
        match validate_handle_wrapper_mut(wrapper_ptr) {
            Some(w) => w,
            None => return create_commitment_error(1),
        }
    };

    let creator_addr = match parse_creator(creator) {
        Some(a) => a,
        None => return create_commitment_error(2),
    };

    let symbol_str = unsafe {
        match CStr::from_ptr(symbol).to_str() {
            Ok(s) => s,
            Err(_) => return create_commitment_error(3),
        }
    };

    let result = tokio::task::block_in_place(|| {
        FFI_RUNTIME.block_on(async {
            let factory = &wrapper.handle.token_factory;
            factory.commit_token_deployment(creator_addr, symbol_str.to_string(), block_number).await
        })
    });

    match result {
        Ok(commitment) => {
            let mut res = Box::new(CommitmentResult {
                commitment: [0u8; 32],
                success: 1,
                error_code: 0,
            });
            res.commitment.copy_from_slice(commitment.as_bytes());
            Box::into_raw(res)
        }
        Err(e) => {
            tracing::error!("Commitment failed: {:?}", e);
            create_commitment_error(4)
        }
    }
}

/// Phase 2: Reveal and deploy after delay
#[no_mangle]
pub extern "C" fn reveal_and_deploy_ffi(
    handle: *mut std::ffi::c_void,
    commitment_hex: *const c_char,
    nonce: *const [u8; 32],  // Nonce from commit phase
    creator: *const c_char,
    name: *const c_char,
    symbol: *const c_char,
    total_supply: *const c_char,
    decimals: u8,
    privacy_enabled: u8,
    block_number: u64,
) -> *mut DualTokenDeployResult {
    let wrapper = unsafe {
        let wrapper_ptr = handle as *mut PrivacySystemHandleWrapper;
        match validate_handle_wrapper_mut(wrapper_ptr) {
            Some(w) => w,
            None => return create_error_result(1),
        }
    };

    // Parse commitment
    let commitment_str = unsafe {
        match CStr::from_ptr(commitment_hex).to_str() {
            Ok(s) => s,
            Err(_) => return create_error_result(2),
        }
    };

    let commitment = match super::common_types::parse_h256(commitment_str) {
        Some(h) => h,
        None => return create_error_result(3),
    };

    // Get nonce
    let nonce_array = unsafe {
        if nonce.is_null() {
            return create_error_result(4);
        }
        *nonce
    };

    // Parse all other parameters (same as deploy_dual_token)
    let _creator_addr = match parse_creator(creator) {
        Some(a) => a,
        None => return create_error_result(5),
    };

    let name_str = unsafe { CStr::from_ptr(name).to_str().unwrap_or("") };
    let symbol_str = unsafe { CStr::from_ptr(symbol).to_str().unwrap_or("") };

    let supply_str = unsafe { CStr::from_ptr(total_supply).to_str().unwrap_or("0") };
    let total_supply = match supply_str.parse::<u128>() {
        Ok(val) => U256::from(val),
        Err(_) => return create_error_result(6),
    };

    // Reveal and deploy
    let result = tokio::task::block_in_place(|| {
        FFI_RUNTIME.block_on(async {
            let factory = &wrapper.handle.token_factory;
            factory.reveal_and_deploy(
                commitment,
                nonce_array,
                name_str.to_string(),
                symbol_str.to_string(),
                total_supply,
                decimals,
                privacy_enabled == 1,
                block_number,
            ).await
        })
    });

    match result {
        Ok((token_id, public_address, private_address)) => {
            // ✅ FIX: Use addresses returned directly from reveal_and_deploy()
            // No need to look up metadata since Rust is now stateless
            let mut result = Box::new(DualTokenDeployResult {
                token_id: [0u8; 32],
                public_address: [0u8; 20],
                private_address: [0u8; 20],
                success: 1,
                error_code: 0,
            });

            result.token_id.copy_from_slice(token_id.0.as_bytes());
            result.public_address.copy_from_slice(public_address.as_bytes());
            result.private_address.copy_from_slice(private_address.as_bytes());

            Box::into_raw(result)
        }
        Err(e) => {
            tracing::error!("Reveal failed: {:?}", e);
            create_error_result(8)
        }
    }
}

/// Check if commitment is ready for reveal
#[no_mangle]
pub extern "C" fn is_commitment_ready_ffi(
    handle: *mut std::ffi::c_void,
    commitment_hex: *const c_char,
    current_block: u64,
) -> u8 {
    let wrapper = unsafe {
        let wrapper_ptr = handle as *mut PrivacySystemHandleWrapper;
        match validate_handle_wrapper_mut(wrapper_ptr) {
            Some(w) => w,
            None => return 0,
        }
    };

    let commitment_str = unsafe {
        match CStr::from_ptr(commitment_hex).to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };

    let commitment = match super::common_types::parse_h256(commitment_str) {
        Some(h) => h,
        None => return 0,
    };

    let result = tokio::task::block_in_place(|| {
        FFI_RUNTIME.block_on(async {
            let factory = &wrapper.handle.token_factory;
            factory.is_commitment_ready(&commitment, current_block).await
        })
    });

    match result {
        Ok(true) => 1,
        _ => 0,
    }
}

#[repr(C)]
pub struct CommitmentResult {
    pub commitment: [u8; 32],
    pub success: u8,
    pub error_code: u32,
}

fn create_commitment_error(error_code: u32) -> *mut CommitmentResult {
    Box::into_raw(Box::new(CommitmentResult {
        commitment: [0u8; 32],
        success: 0,
        error_code,
    }))
}

#[no_mangle]
pub extern "C" fn free_commitment_result(result: *mut CommitmentResult) {
    if !result.is_null() {
        unsafe {
            let _ = Box::from_raw(result);
        }
    }
}

// Helper
fn parse_creator(creator: *const c_char) -> Option<Address> {
    let creator_str = unsafe { CStr::from_ptr(creator).to_str().ok()? };
    parse_address(creator_str)
}
