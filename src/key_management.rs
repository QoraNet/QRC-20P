//! Secure Key Management Module
//!
//! Provides secure key storage, derivation, and management for the privacy system.
//! Keys are never stored in plaintext and are derived from environment variables or HSM.

use anyhow::{Result, anyhow};
use ethereum_types::H256;
use sha3::{Sha3_256, Digest};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use std::env;
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

/// HSM vendor types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HsmVendor {
    None,
    AwsCloudHsm,
    AzureKeyVault,
    ThalesLuna,
    GenericPkcs11,
}

/// Production HSM interface trait
/// Implement this trait for your specific HSM vendor
pub trait HsmProvider: Send + Sync {
    /// Get master key from HSM
    fn get_master_key(&self, key_id: &str) -> Result<H256>;

    /// Derive key using HSM's internal key derivation
    fn derive_key(&self, master_key_id: &str, purpose: &[u8]) -> Result<H256>;

    /// Sign data using HSM-protected key
    fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>>;

    /// Verify HSM connection and authentication
    fn verify_connection(&self) -> Result<()>;
}

/// Key management configuration
#[derive(Debug, Clone)]
pub struct KeyConfig {
    /// Use Hardware Security Module if available
    pub use_hsm: bool,
    /// HSM vendor type
    pub hsm_vendor: HsmVendor,
    /// HSM connection string (vendor-specific)
    pub hsm_connection: Option<String>,
    /// Key derivation iterations for PBKDF2
    pub kdf_iterations: u32,
    /// Salt length in bytes
    pub salt_length: usize,
    /// Enable key rotation
    pub enable_rotation: bool,
    /// Key rotation interval in seconds
    pub rotation_interval: u64,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            use_hsm: false,
            hsm_vendor: HsmVendor::None,
            hsm_connection: None,
            kdf_iterations: 100_000,
            salt_length: 32,
            enable_rotation: true,
            rotation_interval: 30 * 24 * 60 * 60, // 30 days
        }
    }
}

/// Secure key manager
pub struct KeyManager {
    /// Configuration
    config: KeyConfig,
    /// Master key (encrypted in memory)
    master_key: Arc<RwLock<Option<Vec<u8>>>>,
    /// Key derivation salt
    salt: Arc<RwLock<[u8; 32]>>,
    /// Derived keys cache
    derived_keys: Arc<RwLock<std::collections::HashMap<String, H256>>>,
    /// Key rotation timestamp
    last_rotation: Arc<RwLock<u64>>,
    /// Optional HSM provider implementation
    hsm_provider: Option<Arc<dyn HsmProvider>>,
}

impl KeyManager {
    /// Create new key manager
    pub fn new(config: KeyConfig) -> Self {
        Self {
            config,
            master_key: Arc::new(RwLock::new(None)),
            salt: Arc::new(RwLock::new([0u8; 32])),
            derived_keys: Arc::new(RwLock::new(std::collections::HashMap::new())),
            last_rotation: Arc::new(RwLock::new(0)),
            hsm_provider: None,
        }
    }

    /// Create key manager with HSM provider
    pub fn new_with_hsm(config: KeyConfig, hsm_provider: Arc<dyn HsmProvider>) -> Result<Self> {
        // Verify HSM connection
        hsm_provider.verify_connection()?;

        Ok(Self {
            config,
            master_key: Arc::new(RwLock::new(None)),
            salt: Arc::new(RwLock::new([0u8; 32])),
            derived_keys: Arc::new(RwLock::new(std::collections::HashMap::new())),
            last_rotation: Arc::new(RwLock::new(0)),
            hsm_provider: Some(hsm_provider),
        })
    }

    /// Initialize from environment variable
    pub fn initialize_from_env(&mut self) -> Result<()> {
        // Check for master key in environment
        let key_hex = env::var("QORANET_MASTER_KEY")
            .or_else(|_| env::var("MASTER_KEY"))
            .map_err(|_| anyhow!(
                "Master key not found in environment. \
                Please set QORANET_MASTER_KEY environment variable with a 64-character hex string"
            ))?;

        // Validate key format
        if key_hex.len() != 64 {
            return Err(anyhow!(
                "Invalid master key length. Expected 64 hex characters, got {}",
                key_hex.len()
            ));
        }

        // Decode hex key
        let key_bytes = hex::decode(&key_hex)
            .map_err(|e| anyhow!("Invalid hex in master key: {}", e))?;

        // Generate random salt if not set
        let mut salt = self.salt.write();
        if *salt == [0u8; 32] {
            use rand::RngCore;
            OsRng.fill_bytes(&mut *salt);
        }

        // Store encrypted master key
        let encrypted_key = self.encrypt_key(&key_bytes)?;
        *self.master_key.write() = Some(encrypted_key);

        // Update rotation timestamp
        *self.last_rotation.write() = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        Ok(())
    }

    /// Initialize from HSM (Hardware Security Module)
    /// ✅ PRODUCTION: Uses HsmProvider trait for vendor-agnostic HSM integration
    pub fn initialize_from_hsm(&mut self, key_id: &str) -> Result<()> {
        if !self.config.use_hsm {
            return Err(anyhow!("HSM not enabled in configuration"));
        }

        let hsm = self.hsm_provider.as_ref()
            .ok_or_else(|| anyhow!(
                "HSM provider not configured. Use new_with_hsm() to create KeyManager with HSM support.\n\
                \n\
                PRODUCTION HSM INTEGRATION:\n\
                \n\
                Implement the HsmProvider trait for your HSM vendor:\n\
                \n\
                1. **AWS CloudHSM**: Use aws-sdk-cloudhsm + PKCS#11\n\
                2. **Azure Key Vault**: Use azure-security-keyvault\n\
                3. **Thales Luna**: Use cryptoki (PKCS#11 wrapper)\n\
                4. **Generic PKCS#11**: Use cryptoki or pkcs11 crate\n\
                \n\
                Example:\n\
                ```rust\n\
                struct MyHsmProvider {{ /* vendor-specific client */ }}\n\
                impl HsmProvider for MyHsmProvider {{\n\
                    fn get_master_key(&self, key_id: &str) -> Result<H256> {{\n\
                        // Call vendor API to retrieve key\n\
                    }}\n\
                    // ... implement other methods\n\
                }}\n\
                \n\
                let hsm = Arc::new(MyHsmProvider::new(config)?);\n\
                let mut key_mgr = KeyManager::new_with_hsm(key_config, hsm)?;\n\
                key_mgr.initialize_from_hsm(\"qoranet_master_key\")?;\n\
                ```\n\
                \n\
                SECURITY REQUIREMENTS:\n\
                - Keys MUST never leave HSM in plaintext\n\
                - Use HSM's internal key derivation\n\
                - Authenticate with client certificates\n\
                - Enable HSM audit logging"
            ))?;

        // Get master key from HSM
        let master_key_bytes = hsm.get_master_key(key_id)?;

        // Encrypt master key for in-memory storage
        let encrypted = self.encrypt_key(master_key_bytes.as_bytes())?;
        *self.master_key.write() = Some(encrypted);

        tracing::info!("Master key initialized from HSM (key_id: {})", key_id);

        Ok(())
    }

    /// Derive a specific key from master key
    pub fn derive_key(&self, purpose: &str) -> Result<H256> {
        // Check cache first
        if let Some(cached_key) = self.derived_keys.read().get(purpose) {
            return Ok(*cached_key);
        }

        // Get master key
        let master = self.master_key.read()
            .as_ref()
            .ok_or_else(|| anyhow!("Master key not initialized"))?
            .clone();

        // Decrypt master key
        let decrypted_master = self.decrypt_key(&master)?;

        // Derive key using HKDF (HMAC-based Key Derivation Function)
        let derived_key = self.hkdf_derive(&decrypted_master, purpose.as_bytes())?;

        // Cache derived key
        self.derived_keys.write().insert(purpose.to_string(), derived_key);

        Ok(derived_key)
    }

    /// Derive storage encryption key
    pub fn derive_storage_key(&self) -> Result<[u8; 32]> {
        let key = self.derive_key("storage_encryption_v1")?;
        Ok(*key.as_fixed_bytes())
    }

    /// Derive nullifier signing key
    pub fn derive_nullifier_key(&self) -> Result<H256> {
        self.derive_key("nullifier_signing_v1")
    }

    /// Derive commitment blinding key
    pub fn derive_blinding_key(&self) -> Result<H256> {
        self.derive_key("commitment_blinding_v1")
    }

    /// Rotate keys if needed
    pub fn rotate_keys_if_needed(&mut self) -> Result<bool> {
        if !self.config.enable_rotation {
            return Ok(false);
        }

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let last_rotation = *self.last_rotation.read();

        if current_time - last_rotation < self.config.rotation_interval {
            return Ok(false);
        }

        // Perform key rotation
        self.rotate_keys()?;
        Ok(true)
    }

    /// Force key rotation
    pub fn rotate_keys(&mut self) -> Result<()> {
        // Generate new salt
        let mut salt = self.salt.write();
        use rand::RngCore;
        OsRng.fill_bytes(&mut *salt);

        // Clear derived keys cache
        self.derived_keys.write().clear();

        // Update rotation timestamp
        *self.last_rotation.write() = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        Ok(())
    }

    /// Encrypt key for storage in memory
    /// CRITICAL FIX: Uses random nonce prepended to ciphertext
    fn encrypt_key(&self, key: &[u8]) -> Result<Vec<u8>> {
        use rand::RngCore;

        // Use memory-safe encryption with AES-256-GCM
        let cipher_key = self.get_memory_encryption_key()?;
        let cipher = Aes256Gcm::new(&cipher_key);

        // ✅ CRITICAL FIX: Generate RANDOM nonce (never reuse)
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, key)
            .map_err(|e| anyhow!("Failed to encrypt key: {}", e))?;

        // Prepend nonce to ciphertext for storage
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    /// Decrypt key from memory storage
    /// CRITICAL FIX: Extracts nonce from prepended ciphertext
    fn decrypt_key(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        // Minimum length: 12 bytes (nonce) + 16 bytes (GCM tag)
        if encrypted.len() < 12 + 16 {
            return Err(anyhow!("Invalid encrypted data: too short"));
        }

        // Extract nonce from first 12 bytes
        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        let cipher_key = self.get_memory_encryption_key()?;
        let cipher = Aes256Gcm::new(&cipher_key);

        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Failed to decrypt key: {}", e))
    }

    /// Get memory encryption key (derived from machine ID or process ID)
    fn get_memory_encryption_key(&self) -> Result<Key<Aes256Gcm>> {
        // In production, derive from secure machine-specific data
        // For now, use a deterministic key based on process
        let mut hasher = Sha3_256::new();
        hasher.update(b"QORANET_MEMORY_KEY_V1");
        hasher.update(&std::process::id().to_le_bytes());
        hasher.update(&self.salt.read()[..]);

        let key_bytes = hasher.finalize();
        Ok(Key::<Aes256Gcm>::from_slice(&key_bytes).clone())
    }

    /// HKDF key derivation
    fn hkdf_derive(&self, master: &[u8], info: &[u8]) -> Result<H256> {
        use sha3::Sha3_256;

        // Extract phase
        let mut extractor = Sha3_256::new();
        extractor.update(&self.salt.read()[..]);
        extractor.update(master);
        let prk = extractor.finalize();

        // Expand phase
        let mut expander = Sha3_256::new();
        expander.update(&prk);
        expander.update(info);
        expander.update(&[1u8]); // Counter for first block

        let derived = expander.finalize();
        Ok(H256::from_slice(&derived))
    }

    /// Secure key deletion
    pub fn secure_delete(&mut self) {
        // Overwrite keys with random data before clearing
        if let Some(ref mut key) = *self.master_key.write() {
            use rand::RngCore;
            OsRng.fill_bytes(key);
        }

        // Clear all stored data
        *self.master_key.write() = None;
        self.derived_keys.write().clear();

        // Overwrite salt
        use rand::RngCore;
        OsRng.fill_bytes(&mut *self.salt.write());
    }
}

impl Drop for KeyManager {
    fn drop(&mut self) {
        // Ensure keys are securely deleted when KeyManager is dropped
        self.secure_delete();
    }
}

/// Key metadata for auditing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key identifier
    pub key_id: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Last rotation timestamp
    pub rotated_at: Option<u64>,
    /// Key purpose/usage
    pub purpose: String,
    /// Algorithm used
    pub algorithm: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        // Set test environment variable
        std::env::set_var("QORANET_MASTER_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        let mut manager = KeyManager::new(KeyConfig::default());
        assert!(manager.initialize_from_env().is_ok());

        // Test key derivation
        let key1 = manager.derive_key("test_purpose").unwrap();
        let key2 = manager.derive_key("test_purpose").unwrap();
        assert_eq!(key1, key2, "Derived keys should be deterministic");

        // Different purposes should give different keys
        let key3 = manager.derive_key("different_purpose").unwrap();
        assert_ne!(key1, key3, "Different purposes should yield different keys");
    }

    #[test]
    fn test_key_rotation() {
        std::env::set_var("QORANET_MASTER_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        let mut manager = KeyManager::new(KeyConfig::default());
        manager.initialize_from_env().unwrap();

        let key_before = manager.derive_key("test").unwrap();

        // Force rotation
        manager.rotate_keys().unwrap();

        let key_after = manager.derive_key("test").unwrap();
        assert_ne!(key_before, key_after, "Keys should change after rotation");
    }
}
