//! Stealth Address Manager for privacy payments
//!
//! PRODUCTION IMPLEMENTATION with proper ECDH and cryptographic security

use ethereum_types::{Address, H256};
use secp256k1::{PublicKey, SecretKey, Secp256k1, ecdh::SharedSecret};
use sha3::{Keccak256, Digest};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};

/// Stealth address manager with proper ECDH implementation
pub struct StealthAddressManager {
    secp: Secp256k1<secp256k1::All>,
}

impl StealthAddressManager {
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }

    /// Generate a stealth address for a receiver - PRODUCTION IMPLEMENTATION
    pub fn generate_stealth_address_full(
        &self,
        receiver_pubkey: &PublicKey,  // Receiver's published public key (NOT address!)
    ) -> Result<(Address, PublicKey, H256)> {
        // Generate ephemeral keypair
        let ephemeral_secret = SecretKey::new(&mut rand::thread_rng());
        let ephemeral_pubkey = PublicKey::from_secret_key(&self.secp, &ephemeral_secret);

        // CRITICAL: Compute shared secret using proper ECDH
        let shared_secret = SharedSecret::new(receiver_pubkey, &ephemeral_secret);

        // Hash shared secret to get scalar for key derivation
        let mut hasher = Keccak256::new();
        hasher.update(shared_secret.as_ref());
        let hash = hasher.finalize();

        // Create stealth public key: P_stealth = P_receiver + Hash(S) * G
        let secret_scalar = SecretKey::from_slice(&hash)
            .map_err(|e| anyhow!("Invalid scalar from hash: {}", e))?;

        let stealth_pubkey = receiver_pubkey.add_exp_tweak(&self.secp, &secret_scalar.into())
            .map_err(|_| anyhow!("Failed to create stealth public key"))?;

        // Derive Ethereum address from stealth public key
        let stealth_address = self.pubkey_to_address(&stealth_pubkey);

        // Return address, ephemeral pubkey (for blockchain), and shared secret hash
        Ok((stealth_address, ephemeral_pubkey, H256::from_slice(&hash)))
    }

    /// Recover the private key for a stealth address - PRODUCTION IMPLEMENTATION
    pub fn recover_stealth_private_key(
        &self,
        receiver_secret: &SecretKey,
        ephemeral_pubkey: &PublicKey,
    ) -> Result<SecretKey> {
        // CRITICAL: Compute shared secret using proper ECDH
        let shared_secret = SharedSecret::new(ephemeral_pubkey, receiver_secret);

        // Hash to get the same scalar used in generation
        let mut hasher = Keccak256::new();
        hasher.update(shared_secret.as_ref());
        let hash = hasher.finalize();

        // Create stealth private key: k_stealth = k_receiver + Hash(S)
        let secret_scalar = SecretKey::from_slice(&hash)
            .map_err(|e| anyhow!("Invalid scalar from hash: {}", e))?;

        let stealth_secret = receiver_secret.add_tweak(&secret_scalar.into())
            .map_err(|_| anyhow!("Failed to create stealth private key"))?;

        Ok(stealth_secret)
    }

    /// Check if a stealth address belongs to you
    pub fn is_stealth_address_mine(
        &self,
        receiver_secret: &SecretKey,
        ephemeral_pubkey: &PublicKey,
        stealth_address: &Address,
    ) -> bool {
        // Try to recover the private key
        match self.recover_stealth_private_key(receiver_secret, ephemeral_pubkey) {
            Ok(stealth_secret) => {
                // Derive public key from recovered private key
                let recovered_pubkey = PublicKey::from_secret_key(&self.secp, &stealth_secret);
                let recovered_address = self.pubkey_to_address(&recovered_pubkey);

                // Check if it matches the stealth address
                recovered_address == *stealth_address
            }
            Err(_) => false,
        }
    }

    /// Scan multiple ephemeral keys to find your stealth payments
    pub fn scan_for_payments(
        &self,
        receiver_secret: &SecretKey,
        ephemeral_pubkeys: &[(PublicKey, Address)],
    ) -> Vec<Address> {
        let mut found_addresses = Vec::new();

        for (ephemeral_pubkey, stealth_address) in ephemeral_pubkeys {
            if self.is_stealth_address_mine(receiver_secret, ephemeral_pubkey, stealth_address) {
                found_addresses.push(*stealth_address);
            }
        }

        found_addresses
    }

    /// Convert public key to Ethereum address using proper derivation
    fn pubkey_to_address(&self, pubkey: &PublicKey) -> Address {
        let pubkey_bytes = pubkey.serialize_uncompressed();

        // Ethereum address is last 20 bytes of keccak256(pubkey[1..])
        let mut hasher = Keccak256::new();
        hasher.update(&pubkey_bytes[1..]); // Skip format byte (0x04)
        let hash = hasher.finalize();

        Address::from_slice(&hash[12..])  // Last 20 bytes
    }

    /// Generate a viewing keypair for publishing
    pub fn generate_viewing_keypair(&self) -> (SecretKey, PublicKey) {
        let secret = SecretKey::new(&mut rand::thread_rng());
        let pubkey = PublicKey::from_secret_key(&self.secp, &secret);
        (secret, pubkey)
    }

    /// Legacy async wrapper for compatibility
    pub async fn generate_stealth_address(&self, receiver_pubkey: &PublicKey) -> Result<(Address, PublicKey)> {
        let (addr, ephemeral, _) = self.generate_stealth_address_full(receiver_pubkey)?;
        Ok((addr, ephemeral))
    }

    /// Legacy async wrapper for compatibility
    pub async fn recover_stealth_key(
        &self,
        ephemeral_pubkey: &PublicKey,
        receiver_secret: &SecretKey,
    ) -> Result<SecretKey> {
        self.recover_stealth_private_key(receiver_secret, ephemeral_pubkey)
    }
}

/// Stealth address metadata to store on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthPayment {
    pub stealth_address: Address,
    pub ephemeral_pubkey: PublicKey,
    pub amount: u64,
    pub token_id: Option<H256>,
    pub timestamp: u64,
}

/// Published viewing key for receiving stealth payments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthViewingKey {
    pub public_key: PublicKey,
    pub metadata: Option<String>,
}
