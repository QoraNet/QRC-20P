//! FFI Input Validation Module
//!
//! Validates all inputs from Go before processing to prevent crashes and attacks

use anyhow::{Result, anyhow};
use ethereum_types::{Address, H256, U256};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum allowed amount for transactions (1 billion tokens)
const MAX_TRANSACTION_AMOUNT: u64 = 1_000_000_000;

/// Maximum proof size in bytes
/// - Actual Halo2 proofs: 256-384 bytes
/// - Set to 10KB to allow for future proof types
/// - Prevents memory exhaustion attacks
const MAX_PROOF_SIZE: usize = 10_240;

/// Maximum number of nullifiers per transaction
const MAX_NULLIFIERS_PER_TX: usize = 100;

/// Maximum number of commitments per transaction
pub const MAX_COMMITMENTS_PER_TX: usize = 100;

/// DOS protection: Track validation failures
static VALIDATION_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Record validation failure (for monitoring/rate limiting)
fn record_validation_failure() {
    let failures = VALIDATION_FAILURES.fetch_add(1, Ordering::Relaxed);
    if failures % 100 == 0 {
        tracing::warn!("Validation failures: {}", failures);
    }
}

/// Get validation failure count (for metrics)
#[no_mangle]
pub extern "C" fn get_validation_failure_count() -> u64 {
    VALIDATION_FAILURES.load(Ordering::Relaxed)
}

/// Sanitize string for safe logging (prevent log injection)
fn sanitize_for_log(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .take(100) // Limit length
        .collect()
}

/// Validate C string pointer and convert to Rust string
pub unsafe fn validate_c_string(ptr: *const c_char, field_name: &str) -> Result<String> {
    if ptr.is_null() {
        return Err(anyhow!("{} is null", field_name));
    }

    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|e| anyhow!("Invalid UTF-8 in {}: {}", field_name, e))
        .map(|s| s.to_string())
}

/// Validate Ethereum address format
pub fn validate_address(addr_str: &str) -> Result<Address> {
    // Check format
    if !addr_str.starts_with("0x") && !addr_str.starts_with("0X") {
        tracing::warn!("Invalid address format: {}", sanitize_for_log(addr_str));
        record_validation_failure();
        return Err(anyhow!("Address must start with 0x"));
    }

    // Remove 0x prefix
    let hex_str = &addr_str[2..];

    // Check length (40 hex chars = 20 bytes)
    if hex_str.len() != 40 {
        tracing::warn!("Invalid address length: {}", sanitize_for_log(addr_str));
        record_validation_failure();
        return Err(anyhow!(
            "Address must be 40 hex characters (excluding 0x), got {}",
            hex_str.len()
        ));
    }

    // Validate hex characters
    if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        tracing::warn!("Invalid address hex: {}", sanitize_for_log(addr_str));
        record_validation_failure();
        return Err(anyhow!("Address contains invalid hex characters"));
    }

    // Parse address
    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("Failed to decode address: {}", sanitize_for_log(addr_str));
            record_validation_failure();
            return Err(anyhow!("Failed to decode address hex: {}", e));
        }
    };

    if bytes.len() != 20 {
        record_validation_failure();
        return Err(anyhow!("Address must be exactly 20 bytes"));
    }

    // Validate checksum if address has mixed case (EIP-55)
    if addr_str[2..].chars().any(|c| c.is_ascii_uppercase()) &&
       addr_str[2..].chars().any(|c| c.is_ascii_lowercase()) {
        if let Err(e) = validate_checksum_address(addr_str) {
            tracing::warn!("Invalid address checksum: {}", sanitize_for_log(addr_str));
            record_validation_failure();
            return Err(e);
        }
    }

    Ok(Address::from_slice(&bytes))
}

/// Validate EIP-55 checksum address
fn validate_checksum_address(addr_str: &str) -> Result<()> {
    use sha3::{Digest, Keccak256};

    let addr_lower = addr_str[2..].to_lowercase();
    let mut hasher = Keccak256::new();
    hasher.update(addr_lower.as_bytes());
    let hash = hasher.finalize();

    for (i, ch) in addr_str[2..].chars().enumerate() {
        if ch.is_ascii_alphabetic() {
            let hash_byte = hash[i / 2];
            let hash_nibble = if i % 2 == 0 {
                hash_byte >> 4
            } else {
                hash_byte & 0x0f
            };

            if hash_nibble >= 8 {
                if !ch.is_ascii_uppercase() {
                    return Err(anyhow!("Invalid checksum at position {}", i));
                }
            } else {
                if !ch.is_ascii_lowercase() {
                    return Err(anyhow!("Invalid checksum at position {}", i));
                }
            }
        }
    }

    Ok(())
}

/// Validate H256 hex string
pub fn validate_h256(hex_str: &str) -> Result<H256> {
    // Check format
    if !hex_str.starts_with("0x") && !hex_str.starts_with("0X") {
        return Err(anyhow!("H256 must start with 0x"));
    }

    let hex_str = &hex_str[2..];

    // Check length (64 hex chars = 32 bytes)
    if hex_str.len() != 64 {
        return Err(anyhow!(
            "H256 must be 64 hex characters (excluding 0x), got {}",
            hex_str.len()
        ));
    }

    // Validate hex characters
    if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("H256 contains invalid hex characters"));
    }

    // Parse H256
    let bytes = hex::decode(hex_str)
        .map_err(|e| anyhow!("Failed to decode H256: {}", e))?;

    if bytes.len() != 32 {
        return Err(anyhow!("H256 must be exactly 32 bytes"));
    }

    Ok(H256::from_slice(&bytes))
}

/// Validate transaction amount
pub fn validate_amount(amount: u64) -> Result<U256> {
    if amount == 0 {
        return Err(anyhow!("Amount must be greater than 0"));
    }

    if amount > MAX_TRANSACTION_AMOUNT {
        return Err(anyhow!(
            "Amount exceeds maximum allowed: {} > {}",
            amount, MAX_TRANSACTION_AMOUNT
        ));
    }

    Ok(U256::from(amount))
}

/// Validate proof data
pub fn validate_proof(proof: &[u8]) -> Result<()> {
    if proof.is_empty() {
        return Err(anyhow!("Proof cannot be empty"));
    }

    if proof.len() > MAX_PROOF_SIZE {
        return Err(anyhow!(
            "Proof size exceeds maximum: {} > {}",
            proof.len(), MAX_PROOF_SIZE
        ));
    }

    // Check for all zeros (invalid proof)
    if proof.iter().all(|&b| b == 0) {
        return Err(anyhow!("Invalid proof: all zeros"));
    }

    // Check minimum size for valid proof
    if proof.len() < 192 {
        return Err(anyhow!(
            "Proof too small: expected at least 192 bytes, got {}",
            proof.len()
        ));
    }

    Ok(())
}

/// Validate nullifiers array
pub fn validate_nullifiers(nullifiers: &[u8], count: usize) -> Result<Vec<H256>> {
    if count == 0 {
        return Ok(Vec::new());
    }

    if count > MAX_NULLIFIERS_PER_TX {
        return Err(anyhow!(
            "Too many nullifiers: {} > {}",
            count, MAX_NULLIFIERS_PER_TX
        ));
    }

    let expected_size = count * 32;
    if nullifiers.len() != expected_size {
        return Err(anyhow!(
            "Invalid nullifiers size: expected {}, got {}",
            expected_size, nullifiers.len()
        ));
    }

    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * 32;
        let end = start + 32;
        let nullifier = H256::from_slice(&nullifiers[start..end]);

        // Check not zero (invalid nullifier)
        if nullifier == H256::zero() {
            return Err(anyhow!("Invalid nullifier at index {}: zero value", i));
        }

        result.push(nullifier);
    }

    Ok(result)
}

/// Validate commitments array
pub fn validate_commitments(commitments: &[u8], count: usize) -> Result<Vec<H256>> {
    if count == 0 {
        return Ok(Vec::new());
    }

    if count > MAX_COMMITMENTS_PER_TX {
        return Err(anyhow!(
            "Too many commitments: {} > {}",
            count, MAX_COMMITMENTS_PER_TX
        ));
    }

    let expected_size = count * 32;
    if commitments.len() != expected_size {
        return Err(anyhow!(
            "Invalid commitments size: expected {}, got {}",
            expected_size, commitments.len()
        ));
    }

    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * 32;
        let end = start + 32;
        let commitment = H256::from_slice(&commitments[start..end]);

        // Check not zero (invalid commitment)
        if commitment == H256::zero() {
            return Err(anyhow!("Invalid commitment at index {}: zero value", i));
        }

        result.push(commitment);
    }

    Ok(result)
}

/// Validate H256 nullifiers array (safer version)
pub fn validate_nullifiers_h256(nullifiers: &[H256]) -> Result<Vec<H256>> {
    if nullifiers.is_empty() {
        return Ok(Vec::new());
    }

    if nullifiers.len() > MAX_NULLIFIERS_PER_TX {
        return Err(anyhow!(
            "Too many nullifiers: {} > {}",
            nullifiers.len(), MAX_NULLIFIERS_PER_TX
        ));
    }

    for (i, nullifier) in nullifiers.iter().enumerate() {
        if *nullifier == H256::zero() {
            return Err(anyhow!("Invalid nullifier at index {}: zero value", i));
        }
    }

    Ok(nullifiers.to_vec())
}

/// Validate H256 commitments array (safer version)
pub fn validate_commitments_h256(commitments: &[H256]) -> Result<Vec<H256>> {
    if commitments.is_empty() {
        return Ok(Vec::new());
    }

    if commitments.len() > MAX_COMMITMENTS_PER_TX {
        return Err(anyhow!(
            "Too many commitments: {} > {}",
            commitments.len(), MAX_COMMITMENTS_PER_TX
        ));
    }

    for (i, commitment) in commitments.iter().enumerate() {
        if *commitment == H256::zero() {
            return Err(anyhow!("Invalid commitment at index {}: zero value", i));
        }
    }

    Ok(commitments.to_vec())
}

/// Validate proof version is supported
pub fn validate_proof_version(version: u8) -> Result<()> {
    match version {
        1 | 2 => Ok(()),
        v => {
            record_validation_failure();
            Err(anyhow!("Unsupported proof version: {}", v))
        }
    }
}

/// Validate circuit parameters
pub fn validate_circuit_params(k: u32, lookup_bits: usize) -> Result<()> {
    // k must be reasonable (10-16 for production)
    if k < 10 || k > 16 {
        record_validation_failure();
        return Err(anyhow!("Circuit degree k must be 10-16, got {}", k));
    }

    // lookup_bits must be reasonable (0-16)
    if lookup_bits > 16 {
        record_validation_failure();
        return Err(anyhow!("lookup_bits must be 0-16, got {}", lookup_bits));
    }

    Ok(())
}

/// Validate pointer is not null and properly aligned
pub unsafe fn validate_pointer<T>(ptr: *const T, type_name: &str) -> Result<()> {
    if ptr.is_null() {
        return Err(anyhow!("{} pointer is null", type_name));
    }

    // Check alignment
    if ptr.align_offset(std::mem::align_of::<T>()) != 0 {
        return Err(anyhow!("{} pointer is misaligned", type_name));
    }

    Ok(())
}

/// Validate mutable pointer
pub unsafe fn validate_mut_pointer<T>(ptr: *mut T, type_name: &str) -> Result<()> {
    validate_pointer(ptr as *const T, type_name)
}

/// Validate byte array pointer and size
pub unsafe fn validate_byte_array(ptr: *const u8, size: usize, name: &str) -> Result<&'static [u8]> {
    if ptr.is_null() {
        return Err(anyhow!("{} pointer is null", name));
    }

    if size == 0 {
        return Err(anyhow!("{} size is zero", name));
    }

    if size > 10 * 1024 * 1024 { // 10MB max
        return Err(anyhow!("{} size too large: {} bytes", name, size));
    }

    Ok(std::slice::from_raw_parts(ptr, size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_validation() {
        // Valid addresses
        assert!(validate_address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb8").is_ok());
        assert!(validate_address("0x0000000000000000000000000000000000000000").is_ok());

        // Invalid addresses
        assert!(validate_address("742d35Cc6634C0532925a3b844Bc9e7595f0bEb8").is_err()); // No 0x
        assert!(validate_address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb").is_err()); // Too short
        assert!(validate_address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb8X").is_err()); // Too long
        assert!(validate_address("0xZZZZ35Cc6634C0532925a3b844Bc9e7595f0bEb8").is_err()); // Invalid hex
    }

    #[test]
    fn test_h256_validation() {
        // Valid H256
        let valid = format!("0x{}", "0".repeat(64));
        assert!(validate_h256(&valid).is_ok());

        // Invalid H256
        assert!(validate_h256(&format!("0x{}", "0".repeat(63))).is_err()); // Too short
        assert!(validate_h256(&format!("0x{}", "0".repeat(65))).is_err()); // Too long
        assert!(validate_h256(&format!("0x{}", "G".repeat(64))).is_err()); // Invalid hex
    }

    #[test]
    fn test_amount_validation() {
        assert!(validate_amount(1).is_ok());
        assert!(validate_amount(1000).is_ok());

        assert!(validate_amount(0).is_err()); // Zero amount
        assert!(validate_amount(u64::MAX).is_err()); // Too large
    }

    #[test]
    fn test_proof_validation() {
        let valid_proof = vec![1u8; 192];
        assert!(validate_proof(&valid_proof).is_ok());

        assert!(validate_proof(&[]).is_err()); // Empty
        assert!(validate_proof(&vec![0u8; 192]).is_err()); // All zeros
        assert!(validate_proof(&vec![1u8; 100]).is_err()); // Too small
        assert!(validate_proof(&vec![1u8; 11_000]).is_err()); // Too large
    }
}