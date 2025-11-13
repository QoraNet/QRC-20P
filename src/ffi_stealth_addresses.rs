//! FFI bindings for stealth address functionality

use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

use super::ffi::{validate_handle_wrapper, PrivacySystemHandleWrapper};
use secp256k1::{PublicKey, SecretKey};
use ethereum_types::Address;

/// Generate a stealth address for a recipient
///
/// # Arguments
/// * `handle` - Privacy system handle
/// * `receiver_pubkey_hex` - Recipient's public key (hex-encoded, 66 chars)
/// * `stealth_address_out` - Output buffer for stealth address (20 bytes)
/// * `ephemeral_pubkey_out` - Output buffer for ephemeral public key (33 bytes compressed)
///
/// # Returns
/// 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn privacy_generate_stealth_address(
    handle: *const PrivacySystemHandleWrapper,
    receiver_pubkey_hex: *const c_char,
    stealth_address_out: *mut u8,
    ephemeral_pubkey_out: *mut u8,
) -> i32 {
    let wrapper = match unsafe { validate_handle_wrapper(handle) } {
        Some(w) => w,
        None => return -1,
    };

    let pubkey_str = match unsafe { CStr::from_ptr(receiver_pubkey_hex).to_str() } {
        Ok(s) => s,
        Err(_) => return -1,
    };

    // Parse hex public key
    let pubkey_bytes = match hex::decode(pubkey_str.trim_start_matches("0x")) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };

    let receiver_pubkey = match PublicKey::from_slice(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return -1,
    };

    // Generate stealth address
    let (stealth_addr, ephemeral_pk, _) = match wrapper.handle.stealth_manager
        .generate_stealth_address_full(&receiver_pubkey) {
        Ok(result) => result,
        Err(_) => return -1,
    };

    // Copy stealth address (20 bytes)
    unsafe {
        ptr::copy_nonoverlapping(stealth_addr.as_bytes().as_ptr(), stealth_address_out, 20);
    }

    // Copy ephemeral public key (compressed, 33 bytes)
    let ephemeral_bytes = ephemeral_pk.serialize();
    unsafe {
        ptr::copy_nonoverlapping(ephemeral_bytes.as_ptr(), ephemeral_pubkey_out, 33);
    }

    0
}

/// Recover stealth private key from ephemeral public key
///
/// # Arguments
/// * `handle` - Privacy system handle
/// * `receiver_secret_hex` - Recipient's private key (hex-encoded, 64 chars)
/// * `ephemeral_pubkey` - Ephemeral public key (33 bytes compressed)
/// * `stealth_secret_out` - Output buffer for stealth private key (32 bytes)
///
/// # Returns
/// 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn privacy_recover_stealth_key(
    handle: *const PrivacySystemHandleWrapper,
    receiver_secret_hex: *const c_char,
    ephemeral_pubkey: *const u8,
    stealth_secret_out: *mut u8,
) -> i32 {
    let wrapper = match unsafe { validate_handle_wrapper(handle) } {
        Some(w) => w,
        None => return -1,
    };

    let secret_str = match unsafe { CStr::from_ptr(receiver_secret_hex).to_str() } {
        Ok(s) => s,
        Err(_) => return -1,
    };

    // Parse secret key
    let secret_bytes = match hex::decode(secret_str.trim_start_matches("0x")) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };

    let receiver_secret = match SecretKey::from_slice(&secret_bytes) {
        Ok(sk) => sk,
        Err(_) => return -1,
    };

    // Parse ephemeral public key
    let ephemeral_bytes = unsafe { slice::from_raw_parts(ephemeral_pubkey, 33) };
    let ephemeral_pk = match PublicKey::from_slice(ephemeral_bytes) {
        Ok(pk) => pk,
        Err(_) => return -1,
    };

    // Recover stealth private key
    let stealth_secret = match wrapper.handle.stealth_manager
        .recover_stealth_private_key(&receiver_secret, &ephemeral_pk) {
        Ok(sk) => sk,
        Err(_) => return -1,
    };

    // Copy stealth secret (32 bytes)
    unsafe {
        ptr::copy_nonoverlapping(stealth_secret.as_ref().as_ptr(), stealth_secret_out, 32);
    }

    0
}

/// Check if a stealth address belongs to you
///
/// # Arguments
/// * `handle` - Privacy system handle
/// * `receiver_secret_hex` - Your private key (hex-encoded)
/// * `ephemeral_pubkey` - Ephemeral public key from transaction (33 bytes)
/// * `stealth_address` - Stealth address to check (20 bytes)
///
/// # Returns
/// 1 if address is yours, 0 if not, -1 on error
#[no_mangle]
pub extern "C" fn privacy_is_stealth_address_mine(
    handle: *const PrivacySystemHandleWrapper,
    receiver_secret_hex: *const c_char,
    ephemeral_pubkey: *const u8,
    stealth_address: *const u8,
) -> i32 {
    let wrapper = match unsafe { validate_handle_wrapper(handle) } {
        Some(w) => w,
        None => return -1,
    };

    let secret_str = match unsafe { CStr::from_ptr(receiver_secret_hex).to_str() } {
        Ok(s) => s,
        Err(_) => return -1,
    };

    // Parse secret key
    let secret_bytes = match hex::decode(secret_str.trim_start_matches("0x")) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };

    let receiver_secret = match SecretKey::from_slice(&secret_bytes) {
        Ok(sk) => sk,
        Err(_) => return -1,
    };

    // Parse ephemeral public key
    let ephemeral_bytes = unsafe { slice::from_raw_parts(ephemeral_pubkey, 33) };
    let ephemeral_pk = match PublicKey::from_slice(ephemeral_bytes) {
        Ok(pk) => pk,
        Err(_) => return -1,
    };

    // Parse stealth address
    let addr_bytes = unsafe { slice::from_raw_parts(stealth_address, 20) };
    let addr = Address::from_slice(addr_bytes);

    // Check if it's mine
    let is_mine = wrapper.handle.stealth_manager
        .is_stealth_address_mine(&receiver_secret, &ephemeral_pk, &addr);

    if is_mine { 1 } else { 0 }
}

/// Generate a viewing keypair for publishing
///
/// # Arguments
/// * `handle` - Privacy system handle
/// * `secret_out` - Output buffer for secret key (32 bytes)
/// * `pubkey_out` - Output buffer for public key (33 bytes compressed)
///
/// # Returns
/// 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn privacy_generate_viewing_keypair(
    handle: *const PrivacySystemHandleWrapper,
    secret_out: *mut u8,
    pubkey_out: *mut u8,
) -> i32 {
    let wrapper = match unsafe { validate_handle_wrapper(handle) } {
        Some(w) => w,
        None => return -1,
    };

    let (secret, pubkey) = wrapper.handle.stealth_manager.generate_viewing_keypair();

    // Copy secret (32 bytes)
    unsafe {
        ptr::copy_nonoverlapping(secret.as_ref().as_ptr(), secret_out, 32);
    }

    // Copy public key (compressed, 33 bytes)
    let pubkey_bytes = pubkey.serialize();
    unsafe {
        ptr::copy_nonoverlapping(pubkey_bytes.as_ptr(), pubkey_out, 33);
    }

    0
}
