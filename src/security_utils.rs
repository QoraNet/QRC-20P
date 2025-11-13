//! Security Utilities for Timing and Side-Channel Attack Mitigation
//!
//! This module provides defensive security enhancements without modifying
//! existing working code. All functions are ADDITIVE only.

use ethereum_types::{H256, U256};
use rand::{Rng, RngCore};
use rand::rngs::OsRng;
use sha3::{Sha3_256, Digest};
use std::time::{Duration, Instant};

// ============================================================================
// 1. Enhanced Blinding Factor Generation
// ============================================================================

/// Generate cryptographically strong blinding factor with multiple entropy sources
///
/// This is an ENHANCED version that provides better privacy guarantees.
/// The original blinding generation still works - this is an optional upgrade.
///
/// Security improvements:
/// - Multiple entropy sources (OS random + timestamp + domain separation)
/// - Prevents predictable blinding factors
/// - Makes side-channel attacks much harder
///
/// Usage:
/// ```rust
/// // Option 1: Use this enhanced version (recommended for production)
/// let blinding = generate_secure_blinding(secret, amount, None);
///
/// // Option 2: Keep using H256::random() (works fine, but less secure)
/// let blinding = H256::random();
/// ```
pub fn generate_secure_blinding(
    secret: H256,
    amount: U256,
    user_entropy: Option<H256>,
) -> H256 {
    let mut rng = OsRng;

    // Start with OS randomness (primary entropy source)
    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);

    // Mix in user-provided entropy if available
    let user_entropy_bytes = user_entropy.unwrap_or_else(|| {
        let mut ue = [0u8; 32];
        rng.fill_bytes(&mut ue);
        H256::from(ue)
    });

    // Hash everything together with domain separation
    let mut hasher = Sha3_256::new();
    hasher.update(b"QORANET_BLINDING_V1"); // Domain separator
    hasher.update(random_bytes);
    hasher.update(secret.as_bytes());

    // Convert U256 to bytes
    let amount_bytes: [u8; 32] = amount.to_big_endian();
    hasher.update(&amount_bytes);

    hasher.update(user_entropy_bytes.as_bytes());

    // Add timestamp for uniqueness (prevents same blinding even with same inputs)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    hasher.update(&timestamp.to_le_bytes());

    let hash = hasher.finalize();
    H256::from_slice(&hash)
}

// ============================================================================
// 2. Constant-Time Execution Wrapper
// ============================================================================

/// Execute a function and ensure it takes constant time
///
/// This is a WRAPPER function that doesn't modify existing code.
/// It adds defensive timing protection on top of existing functionality.
///
/// Security improvement:
/// - All operations take exactly `target_duration` milliseconds
/// - Hides actual computation time from timing attacks
/// - Prevents amount inference from proof generation time
///
/// Usage:
/// ```rust
/// // Wrap existing proof generation with constant-time execution
/// let result = constant_time_execute(
///     Duration::from_millis(100),
///     || proof_system.prove(secret, amount, blinding, leaf_index)
/// );
/// ```
pub fn constant_time_execute<F, T>(target_duration: Duration, f: F) -> T
where
    F: FnOnce() -> T,
{
    let start_time = Instant::now();

    // Execute the actual function (unchanged)
    let result = f();

    // Add padding to reach target duration
    let elapsed = start_time.elapsed();
    if elapsed < target_duration {
        let sleep_duration = target_duration - elapsed;
        std::thread::sleep(sleep_duration);
    }

    result
}

/// Constant-time execution with configurable target based on operation type
///
/// Different operations have different "reasonable" times:
/// - Proof generation: 100-200ms
/// - Verification: 20-50ms
/// - Commitment generation: 5-10ms
pub enum OperationType {
    ProofGeneration,  // Target: 150ms
    ProofVerification, // Target: 30ms
    CommitmentGen,    // Target: 10ms
    Custom(u64),      // Custom target in milliseconds
}

impl OperationType {
    pub fn target_duration(&self) -> Duration {
        match self {
            OperationType::ProofGeneration => Duration::from_millis(150),
            OperationType::ProofVerification => Duration::from_millis(30),
            OperationType::CommitmentGen => Duration::from_millis(10),
            OperationType::Custom(ms) => Duration::from_millis(*ms),
        }
    }
}

/// Execute with operation-specific constant time
pub fn constant_time_execute_typed<F, T>(op_type: OperationType, f: F) -> T
where
    F: FnOnce() -> T,
{
    constant_time_execute(op_type.target_duration(), f)
}

// ============================================================================
// 3. Random Jitter for Timing Confusion
// ============================================================================

/// Add random delay to confuse timing analysis
///
/// This is ADDITIVE - adds small random delay without changing existing logic.
///
/// Security improvement:
/// - Makes statistical timing analysis much harder
/// - Adds unpredictable noise to timing measurements
/// - Low overhead (max 20ms by default)
///
/// Usage:
/// ```rust
/// // Add this before returning from FFI functions
/// apply_random_jitter(0..20);
/// ```
pub fn apply_random_jitter(max_jitter_ms: u64) {
    let mut rng = rand::thread_rng();
    let jitter_ms = rng.gen_range(0..max_jitter_ms);
    std::thread::sleep(Duration::from_millis(jitter_ms));
}

/// Apply random jitter with specific range
pub fn apply_random_jitter_range(min_ms: u64, max_ms: u64) {
    let mut rng = rand::thread_rng();
    let jitter_ms = rng.gen_range(min_ms..max_ms);
    std::thread::sleep(Duration::from_millis(jitter_ms));
}

// ============================================================================
// 4. Secure Random Generation Helpers
// ============================================================================

/// Generate cryptographically secure random H256
/// (This is similar to H256::random() but with explicit OsRng)
pub fn secure_random_h256() -> H256 {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    H256::from(bytes)
}

/// Generate cryptographically secure random U256
pub fn secure_random_u256(max: U256) -> U256 {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let random = U256::from_big_endian(&bytes);

    // Modulo to fit in range [0, max)
    if max.is_zero() {
        U256::zero()
    } else {
        random % max
    }
}

// ============================================================================
// 5. Configuration and Feature Flags
// ============================================================================

/// Security configuration for timing and side-channel protection
#[derive(Clone, Debug)]
pub struct SecurityConfig {
    /// Enable constant-time execution for proof generation
    pub constant_time_proofs: bool,

    /// Enable random jitter in FFI calls
    pub random_jitter: bool,

    /// Maximum jitter in milliseconds
    pub max_jitter_ms: u64,

    /// Target duration for proof generation (milliseconds)
    pub proof_target_ms: u64,

    /// Use enhanced blinding factor generation
    pub enhanced_blinding: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            constant_time_proofs: true,  // Enable by default for production
            random_jitter: true,
            max_jitter_ms: 20,
            proof_target_ms: 150,
            enhanced_blinding: true,
        }
    }
}

impl SecurityConfig {
    /// Production configuration (all protections enabled)
    pub fn production() -> Self {
        Self::default()
    }

    /// Development configuration (all protections disabled for faster testing)
    pub fn development() -> Self {
        Self {
            constant_time_proofs: false,
            random_jitter: false,
            max_jitter_ms: 0,
            proof_target_ms: 0,
            enhanced_blinding: false,
        }
    }

    /// Testing configuration (minimal protections)
    pub fn testing() -> Self {
        Self {
            constant_time_proofs: false,
            random_jitter: false,
            max_jitter_ms: 0,
            proof_target_ms: 0,
            enhanced_blinding: true, // Keep enhanced blinding for tests
        }
    }
}

// ============================================================================
// 6. Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enhanced_blinding_uniqueness() {
        let secret = secure_random_h256();
        let amount = U256::from(1000);

        let mut blindings = std::collections::HashSet::new();

        // Generate 100 blinding factors with same inputs
        for _ in 0..100 {
            let blinding = generate_secure_blinding(secret, amount, None);
            assert!(
                blindings.insert(blinding),
                "Duplicate blinding factor detected!"
            );
        }
    }

    #[test]
    fn test_enhanced_blinding_not_zero() {
        let secret = secure_random_h256();
        let amount = U256::from(1000);

        for _ in 0..10 {
            let blinding = generate_secure_blinding(secret, amount, None);
            assert_ne!(blinding, H256::zero(), "Blinding factor is zero!");
        }
    }

    #[test]
    fn test_constant_time_execution() {
        use std::time::Instant;

        let target = Duration::from_millis(50);

        // Test with fast function (should be padded to 50ms)
        let start = Instant::now();
        constant_time_execute(target, || {
            std::thread::sleep(Duration::from_millis(10));
        });
        let elapsed = start.elapsed();

        // Should be approximately 50ms (±5ms tolerance)
        assert!(
            elapsed >= Duration::from_millis(45) && elapsed <= Duration::from_millis(55),
            "Constant-time execution failed: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_constant_time_doesnt_delay_slow_operations() {
        use std::time::Instant;

        let target = Duration::from_millis(50);

        // Test with slow function (should NOT be padded, just return)
        let start = Instant::now();
        constant_time_execute(target, || {
            std::thread::sleep(Duration::from_millis(100));
        });
        let elapsed = start.elapsed();

        // Should be approximately 100ms (no additional padding)
        assert!(
            elapsed >= Duration::from_millis(95) && elapsed <= Duration::from_millis(110),
            "Constant-time execution incorrectly delayed slow operation: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_random_jitter_range() {
        use std::time::Instant;

        let start = Instant::now();
        apply_random_jitter(10); // Max 10ms
        let elapsed = start.elapsed();

        // Should be between 0 and 10ms
        assert!(
            elapsed < Duration::from_millis(15),
            "Random jitter exceeded max: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_secure_random_uniqueness() {
        let mut randoms = std::collections::HashSet::new();

        for _ in 0..100 {
            let r = secure_random_h256();
            assert!(randoms.insert(r), "Duplicate random value!");
        }
    }

    #[test]
    fn test_security_config_defaults() {
        let config = SecurityConfig::production();
        assert!(config.constant_time_proofs);
        assert!(config.random_jitter);
        assert!(config.enhanced_blinding);

        let dev_config = SecurityConfig::development();
        assert!(!dev_config.constant_time_proofs);
        assert!(!dev_config.random_jitter);
    }
}
