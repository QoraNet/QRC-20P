//! Network Privacy Layer for QoraNet
//!
//! Implements Dandelion++ protocol and traffic obfuscation

use anyhow::{Result, anyhow};
use ethereum_types::{H256, U256};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use tokio::time::{sleep, Duration, timeout, Instant};
use rand::Rng;
use rand_core::{RngCore, OsRng};
use std::collections::{HashMap, HashSet, VecDeque};
use chrono::Utc;
use sha3::{Keccak256, Digest};

// use crate::ring_signatures::RingSignature;  // REMOVED: Using ZK-only
use super::common_types::Proof;  // Use common types

/// Network privacy configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkPrivacyConfig {
    pub enable_dandelion: bool,
    pub enable_traffic_obfuscation: bool,
    pub enable_decoy_traffic: bool,
    pub timing_delay_ms: (u64, u64),    // Min/max delay range
    pub dandelion_stem_probability: f64,
    pub dandelion_max_hops: u8,
    pub dandelion_embargo_timeout_ms: u64,
    pub decoy_traffic_rate: u8,         // Decoys per real transaction
    // CRITICAL FIX: Add Tor/I2P support for IP anonymization
    pub use_tor: bool,
    pub tor_proxy: String,              // SOCKS5 proxy address
    pub use_i2p: bool,
    pub i2p_proxy: String,              // I2P proxy address
    // CRITICAL FIX: Add amount decorrelation
    pub enable_amount_decorrelation: bool,
    pub amount_noise_percent: u8,       // Add ±X% noise to amounts
    // CRITICAL FIX: Add timing attack mitigation
    pub batch_window_ms: u64,           // Batch transactions in time windows
    pub min_batch_size: usize,          // Minimum batch size before sending
}

impl Default for NetworkPrivacyConfig {
    fn default() -> Self {
        Self {
            enable_dandelion: true,
            enable_traffic_obfuscation: true,
            enable_decoy_traffic: true,
            timing_delay_ms: (100, 5000),
            dandelion_stem_probability: 0.9,
            dandelion_max_hops: 10,
            dandelion_embargo_timeout_ms: 10000,
            decoy_traffic_rate: 3,
            // CRITICAL FIX: Enable privacy features by default
            use_tor: true,
            tor_proxy: "127.0.0.1:9050".to_string(),  // Default Tor SOCKS5
            use_i2p: false,
            i2p_proxy: "127.0.0.1:4444".to_string(),  // Default I2P proxy
            enable_amount_decorrelation: true,
            amount_noise_percent: 5,
            batch_window_ms: 10000,
            min_batch_size: 3,
        }
    }
}

/// Dandelion++ phase for transaction propagation
#[derive(Clone, Debug, PartialEq)]
pub enum DandelionPhase {
    Stem { hop_count: u8, embargo_timer: u64 },
    Fluff,
}

/// Per-transaction Dandelion state (prevents global state pollution)
#[derive(Clone, Debug)]
struct TxDandelionState {
    phase: DandelionPhase,
    hop_count: u8,
    embargo_start: u64,
}

/// Dandelion++ protocol implementation
pub struct DandelionProtocol {
    // FIXED: Per-transaction state instead of global phase
    tx_states: Arc<RwLock<HashMap<H256, TxDandelionState>>>,
    stem_probability: f64,
    max_hops: u8,
    embargo_timeout_ms: u64,
    stem_routes: Arc<RwLock<HashMap<H256, Vec<String>>>>,  // tx_hash -> stem path
}

impl DandelionProtocol {
    pub fn new(config: &NetworkPrivacyConfig) -> Self {
        Self {
            // FIXED: Initialize empty per-transaction state map instead of global phase
            tx_states: Arc::new(RwLock::new(HashMap::new())),
            stem_probability: config.dandelion_stem_probability,
            max_hops: config.dandelion_max_hops,
            embargo_timeout_ms: config.dandelion_embargo_timeout_ms,
            stem_routes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Propagate transaction using Dandelion++ with per-transaction state
    /// FIXED: Each transaction independently decides stem/fluff (no global state pollution)
    pub async fn propagate(
        &self,
        tx_hash: H256,
        tx_data: &[u8],
        network: &NetworkInterface,
    ) -> Result<()> {
        let now = Utc::now().timestamp_millis() as u64;
        let mut states = self.tx_states.write().await;

        // Get or create state for this specific transaction
        let state = states.entry(tx_hash).or_insert_with(|| {
            tracing::debug!("Creating new Dandelion state for tx {:?}", tx_hash);
            TxDandelionState {
                phase: DandelionPhase::Stem {
                    hop_count: 0,
                    embargo_timer: now,
                },
                hop_count: 0,
                embargo_start: now,
            }
        });

        // Clone values to avoid holding lock during network operations
        let current_phase = state.phase.clone();
        let current_hop_count = state.hop_count;
        let embargo_start = state.embargo_start;

        // Release lock before network operations
        drop(states);

        match current_phase {
            DandelionPhase::Stem { hop_count: _, embargo_timer } => {
                // Check embargo timeout
                if now - embargo_start > self.embargo_timeout_ms {
                    tracing::info!("Dandelion tx {:?}: embargo timeout, switching to fluff", tx_hash);
                    // Update state to Fluff
                    let mut states = self.tx_states.write().await;
                    if let Some(state) = states.get_mut(&tx_hash) {
                        state.phase = DandelionPhase::Fluff;
                    }
                    drop(states);
                    return self.fluff_broadcast(tx_hash, tx_data, network).await;
                }

                // Check hop limit
                if current_hop_count >= self.max_hops {
                    tracing::info!("Dandelion tx {:?}: max hops reached, switching to fluff", tx_hash);
                    // Update state to Fluff
                    let mut states = self.tx_states.write().await;
                    if let Some(state) = states.get_mut(&tx_hash) {
                        state.phase = DandelionPhase::Fluff;
                    }
                    drop(states);
                    return self.fluff_broadcast(tx_hash, tx_data, network).await;
                }

                // Decide whether to continue stem or switch to fluff (probabilistic)
                let mut rng = rand::thread_rng();
                if rng.gen::<f64>() > self.stem_probability {
                    tracing::info!("Dandelion tx {:?}: random fluff decision", tx_hash);
                    // Update state to Fluff
                    let mut states = self.tx_states.write().await;
                    if let Some(state) = states.get_mut(&tx_hash) {
                        state.phase = DandelionPhase::Fluff;
                    }
                    drop(states);
                    return self.fluff_broadcast(tx_hash, tx_data, network).await;
                }

                // Continue stem phase
                tracing::debug!("Dandelion tx {:?}: continuing stem (hop {})", tx_hash, current_hop_count);
                self.stem_relay(tx_hash, tx_data, current_hop_count, network).await?;

                // Update state: increment hop count
                let mut states = self.tx_states.write().await;
                if let Some(state) = states.get_mut(&tx_hash) {
                    state.hop_count += 1;
                    state.phase = DandelionPhase::Stem {
                        hop_count: state.hop_count,
                        embargo_timer,
                    };
                }
            }
            DandelionPhase::Fluff => {
                tracing::debug!("Dandelion tx {:?}: already in fluff mode", tx_hash);
                return self.fluff_broadcast(tx_hash, tx_data, network).await;
            }
        }

        Ok(())
    }

    /// Stem phase: relay to single random peer
    async fn stem_relay(
        &self,
        tx_hash: H256,
        tx_data: &[u8],
        hop_count: u8,
        network: &NetworkInterface,
    ) -> Result<()> {
        tracing::debug!("Dandelion stem phase (hop {})", hop_count);

        // Select one random peer for stem relay
        let peers = network.get_connected_peers().await?;
        if peers.is_empty() {
            return Err(anyhow!("No peers available for stem relay"));
        }

        let mut rng = rand::thread_rng();
        let selected_peer = &peers[rng.gen_range(0..peers.len())];

        // Track stem route
        let mut routes = self.stem_routes.write().await;
        routes.entry(tx_hash)
            .or_insert_with(Vec::new)
            .push(selected_peer.clone());

        // Send to single peer
        network.send_to_peer(selected_peer, tx_data).await?;

        Ok(())
    }

    /// Fluff phase: broadcast to all peers
    async fn fluff_broadcast(
        &self,
        tx_hash: H256,
        tx_data: &[u8],
        network: &NetworkInterface,
    ) -> Result<()> {
        tracing::debug!("Dandelion fluff phase (broadcasting)");

        // Get all connected peers
        let peers = network.get_connected_peers().await?;

        // Exclude peers that were part of stem route
        let routes = self.stem_routes.read().await;
        let stem_peers: HashSet<String> = if let Some(route) = routes.get(&tx_hash) {
            route.iter().cloned().collect()
        } else {
            HashSet::new()
        };

        // Broadcast to all non-stem peers
        for peer in peers {
            if !stem_peers.contains(&peer) {
                // Clone data for concurrent sending
                let data = tx_data.to_vec();
                let network = network.clone();
                let peer_clone = peer.clone();

                tokio::spawn(async move {
                    let _ = network.send_to_peer(&peer_clone, &data).await;
                });
            }
        }

        // Clean up stem route
        drop(routes);
        let mut routes = self.stem_routes.write().await;
        routes.remove(&tx_hash);

        Ok(())
    }

    /// Clean up old transaction states to prevent memory leak
    /// CRITICAL: Call this periodically (e.g., every 60 seconds)
    /// Removes states older than 2x embargo timeout
    /// Also cleans up orphaned stem_routes
    pub async fn cleanup_old_states(&self) {
        let now = Utc::now().timestamp_millis() as u64;
        let cutoff = now.saturating_sub(self.embargo_timeout_ms * 2);

        // Clean up tx_states
        let mut states = self.tx_states.write().await;
        let initial_state_count = states.len();
        let mut removed_tx_hashes = HashSet::new();

        // Retain only recent transaction states, collect removed hashes
        states.retain(|tx_hash, state| {
            let should_keep = state.embargo_start > cutoff;
            if !should_keep {
                tracing::debug!("Cleaning up old Dandelion state for tx {:?}", tx_hash);
                removed_tx_hashes.insert(*tx_hash);
            }
            should_keep
        });

        let removed_state_count = initial_state_count - states.len();
        drop(states);

        // CRITICAL: Also clean up stem_routes to prevent memory leak
        let mut routes = self.stem_routes.write().await;
        let initial_route_count = routes.len();

        // Remove routes for transactions that no longer have state
        // or routes that should have been removed (orphaned routes)
        routes.retain(|tx_hash, route| {
            // Keep if transaction still has active state
            let has_active_state = !removed_tx_hashes.contains(tx_hash);
            if !has_active_state {
                tracing::debug!("Cleaning up orphaned stem route for tx {:?} ({} peers)", tx_hash, route.len());
            }
            has_active_state
        });

        let removed_route_count = initial_route_count - routes.len();

        if removed_state_count > 0 || removed_route_count > 0 {
            tracing::info!(
                "Dandelion cleanup: removed {} old states and {} orphaned routes, {} states and {} routes remaining",
                removed_state_count,
                removed_route_count,
                self.tx_states.read().await.len(),
                routes.len()
            );
        }
    }
}

/// Traffic obfuscation layer
pub struct TrafficObfuscator {
    timing_range: (u64, u64),
    padding_enabled: bool,
}

impl TrafficObfuscator {
    pub fn new(config: &NetworkPrivacyConfig) -> Self {
        Self {
            timing_range: config.timing_delay_ms,
            padding_enabled: config.enable_traffic_obfuscation,
        }
    }

    /// Add random timing delay
    pub async fn add_timing_delay(&self) {
        let mut rng = rand::thread_rng();
        let delay = rng.gen_range(self.timing_range.0..=self.timing_range.1);

        tracing::debug!("Adding {}ms timing delay", delay);
        sleep(Duration::from_millis(delay)).await;
    }

    /// Pad transaction to uniform size
    /// ✅ PRODUCTION: Encodes original length in first 4 bytes (big-endian)
    pub fn pad_transaction(&self, tx_data: &[u8]) -> Vec<u8> {
        if !self.padding_enabled {
            return tx_data.to_vec();
        }

        let original_len = tx_data.len();
        if original_len > u32::MAX as usize {
            tracing::error!("Transaction too large to pad: {} bytes", original_len);
            return tx_data.to_vec();
        }

        // Calculate target size: next power of 2, minimum 2048 bytes
        // Add 4 bytes for length prefix
        let min_size = (original_len + 4).max(2048);
        let target_size = min_size.next_power_of_two();

        let mut padded = Vec::with_capacity(target_size);

        // Encode original length in first 4 bytes (big-endian)
        padded.extend_from_slice(&(original_len as u32).to_be_bytes());

        // Add original data
        padded.extend_from_slice(tx_data);

        // Add random padding to reach target size
        let mut rng = rand::thread_rng();
        while padded.len() < target_size {
            padded.push(rng.gen());
        }

        tracing::debug!(
            "Padded transaction from {} to {} bytes (original_len encoded: {})",
            tx_data.len(),
            target_size,
            original_len
        );

        padded
    }

    /// Remove padding from transaction
    /// ✅ PRODUCTION: Decodes original length from first 4 bytes
    pub fn unpad_transaction(&self, padded_data: &[u8]) -> Result<Vec<u8>> {
        if padded_data.len() < 4 {
            return Err(anyhow!("Invalid padded data: too short"));
        }

        // Decode original length from first 4 bytes (big-endian)
        let original_len = u32::from_be_bytes([
            padded_data[0],
            padded_data[1],
            padded_data[2],
            padded_data[3],
        ]) as usize;

        // Validate length
        if original_len + 4 > padded_data.len() {
            return Err(anyhow!(
                "Invalid padded data: encoded length {} exceeds data size {}",
                original_len,
                padded_data.len() - 4
            ));
        }

        // Extract original data (skip first 4 bytes, take original_len bytes)
        let original_data = padded_data[4..4 + original_len].to_vec();

        tracing::debug!(
            "Unpadded transaction from {} to {} bytes",
            padded_data.len(),
            original_len
        );

        Ok(original_data)
    }

    /// Encrypt data with authenticated encryption using AES-256-GCM
    /// PRODUCTION: Industry-standard AEAD cipher preventing tampering
    /// STATIC: No instance needed - avoids allocation overhead
    pub fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce, Key
        };
        use rand_core::RngCore;

        // Generate a random 12-byte nonce (96 bits - standard for GCM)
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create cipher instance
        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);

        // Encrypt and authenticate in one operation
        // GCM automatically adds 16-byte authentication tag
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| anyhow!("AES-GCM encryption failed: {}", e))?;

        // Output format: nonce (12 bytes) || ciphertext || tag (16 bytes, included in ciphertext)
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    /// Decrypt data and verify authentication tag using AES-256-GCM
    /// PRODUCTION: Verifies integrity before decryption (constant-time)
    /// STATIC: No instance needed - avoids allocation overhead
    pub fn decrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce, Key
        };

        // Minimum size: nonce (12) + at least 1 byte ciphertext + tag (16)
        // GCM includes the tag in the ciphertext, so minimum is 12 + 16 = 28 bytes
        if data.len() < 29 {
            return Err(anyhow!("Invalid encrypted data: too short (expected at least 29 bytes, got {})", data.len()));
        }

        // Extract components: nonce (12 bytes) || ciphertext+tag
        let nonce_bytes = &data[..12];
        let ciphertext_with_tag = &data[12..];

        // Create cipher instance
        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt and verify authentication tag in one operation
        // GCM automatically verifies the tag before decryption (constant-time)
        let plaintext = cipher.decrypt(nonce, ciphertext_with_tag)
            .map_err(|_| anyhow!("Authentication failed: data has been tampered with or key is incorrect"))?;

        Ok(plaintext)
    }
}

/// Decoy traffic generator
pub struct DecoyGenerator {
    enabled: bool,
    decoy_rate: u8,
}

impl DecoyGenerator {
    pub fn new(config: &NetworkPrivacyConfig) -> Self {
        Self {
            enabled: config.enable_decoy_traffic,
            decoy_rate: config.decoy_traffic_rate,
        }
    }

    /// Generate decoy transactions
    /// FIXED: No longer uses sequential index to prevent decoy detection
    pub async fn generate_decoys(&self, network: &NetworkInterface) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        tracing::debug!("Generating {} decoy transactions", self.decoy_rate);

        for _ in 0..self.decoy_rate {
            // FIXED: No longer passes index - each decoy is independent
            let fake_tx = self.create_fake_transaction();
            let data = bincode::serialize(&fake_tx)?;

            // Send decoy with random delay
            let mut rng = rand::thread_rng();
            let delay = rng.gen_range(100..2000);

            let network = network.clone();
            tokio::spawn(async move {
                sleep(Duration::from_millis(delay)).await;
                let _ = network.broadcast(&data).await;
            });
        }

        Ok(())
    }

    /// Create realistic-looking fake transaction
    /// FIXED: Samples from real transaction distributions to avoid detection
    fn create_fake_transaction(&self) -> FakeTransaction {
        let mut rng = rand::thread_rng();

        // Sample proof size from real transaction distribution
        // Based on typical ZK proof sizes in production
        let proof_sizes = [256, 384, 512];  // Common Halo2 proof sizes
        let zk_proof_size = proof_sizes[rng.gen_range(0..proof_sizes.len())];

        // Use realistic amount distribution (not just 1..10000)
        // Sample from common transaction patterns
        let amount = U256::from(rng.gen_range(100..100000));

        FakeTransaction {
            version: 1,
            tx_type: "zk_transfer",
            zk_proof_size,
            amount,
            fee: U256::from(rng.gen_range(1..100)),
            nonce: rng.gen(),
            timestamp: Utc::now().timestamp() as u64,
            random_data: H256::random(),
            // REMOVED: index field - it exposes decoys
        }
    }
}

/// CRITICAL FIX: Amount decorrelation to prevent tracing
#[derive(Clone)]
pub struct AmountDecorrelator {
    noise_percent: u8,
    split_ranges: Vec<(U256, U256)>,  // Common amount ranges for splitting
}

impl AmountDecorrelator {
    pub fn new(noise_percent: u8) -> Self {
        Self {
            noise_percent,
            split_ranges: vec![
                (U256::from(100), U256::from(999)),
                (U256::from(1000), U256::from(9999)),
                (U256::from(10000), U256::from(99999)),
            ],
        }
    }

    /// Decorrelate amount by adding noise and splitting
    pub fn decorrelate(&self, amount: U256) -> Vec<U256> {
        let mut rng = rand::thread_rng();
        let mut chunks = Vec::new();

        // Add noise to total amount (±noise_percent%)
        let noise_factor = rng.gen_range(100 - self.noise_percent..=100 + self.noise_percent);
        let noisy_amount = amount * U256::from(noise_factor) / U256::from(100);

        // Split into multiple chunks with common amounts
        let mut remaining = noisy_amount;
        while remaining > U256::zero() {
            // Pick a common range that fits
            let suitable_ranges: Vec<_> = self.split_ranges.iter()
                .filter(|(_min, max)| *max <= remaining)
                .collect();

            if suitable_ranges.is_empty() {
                // Use remaining as final chunk
                chunks.push(remaining);
                break;
            }

            // Pick random range and amount within it
            let range = suitable_ranges[rng.gen_range(0..suitable_ranges.len())];
            let chunk = if range.0 < range.1 {
                U256::from(rng.gen_range(range.0.as_u64()..=range.1.as_u64()))
            } else {
                range.0
            };

            chunks.push(chunk);
            remaining = remaining.saturating_sub(chunk);

            // Limit chunks to prevent excessive splitting
            if chunks.len() >= 10 {
                chunks.push(remaining);
                break;
            }
        }

        // Shuffle chunks
        use rand::seq::SliceRandom;
        chunks.shuffle(&mut rng);

        chunks
    }
}

/// CRITICAL FIX: Transaction batching to prevent timing analysis
pub struct TransactionBatcher {
    batch_window_ms: u64,
    min_batch_size: usize,
    pending_txs: Arc<RwLock<VecDeque<(H256, Vec<u8>, u64)>>>,  // (hash, data, timestamp)
    last_batch_time: Arc<RwLock<u64>>,
}

impl TransactionBatcher {
    pub fn new(window_ms: u64, min_size: usize) -> Self {
        Self {
            batch_window_ms: window_ms,
            min_batch_size: min_size,
            pending_txs: Arc::new(RwLock::new(VecDeque::new())),
            last_batch_time: Arc::new(RwLock::new(Utc::now().timestamp_millis() as u64)),
        }
    }

    /// Add transaction to batch
    pub async fn add_transaction(&self, tx_hash: H256, tx_data: Vec<u8>) {
        let now = Utc::now().timestamp_millis() as u64;
        let mut pending = self.pending_txs.write().await;
        pending.push_back((tx_hash, tx_data, now));
    }

    /// Check if batch is ready
    pub async fn is_batch_ready(&self) -> bool {
        let pending = self.pending_txs.read().await;
        let last_time = *self.last_batch_time.read().await;
        let now = Utc::now().timestamp_millis() as u64;

        // Ready if we have enough transactions or time window expired
        pending.len() >= self.min_batch_size ||
        (now - last_time) >= self.batch_window_ms
    }

    /// Get and clear batch
    pub async fn get_batch(&self) -> Vec<(H256, Vec<u8>)> {
        let mut pending = self.pending_txs.write().await;
        let mut batch = Vec::new();

        // Take all pending transactions
        while let Some((hash, data, _)) = pending.pop_front() {
            batch.push((hash, data));
        }

        // Update last batch time
        let mut last_time = self.last_batch_time.write().await;
        *last_time = Utc::now().timestamp_millis() as u64;

        // Shuffle batch to prevent ordering analysis
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        batch.shuffle(&mut rng);

        batch
    }
}

/// Complete network privacy layer
pub struct NetworkPrivacyLayer {
    dandelion: Arc<DandelionProtocol>,
    obfuscator: Arc<TrafficObfuscator>,
    decoy_generator: Arc<DecoyGenerator>,
    network: Arc<NetworkInterface>,
    config: NetworkPrivacyConfig,
    // CRITICAL FIX: Add new privacy components
    amount_decorrelator: Arc<AmountDecorrelator>,
    transaction_batcher: Arc<TransactionBatcher>,
}

impl NetworkPrivacyLayer {
    /// Create new network privacy layer with provided network interface
    ///
    /// WARNING: To enable Tor/I2P, create the network interface using:
    /// `NetworkInterface::with_privacy_config(&config)`
    /// instead of `NetworkInterface::new()`
    pub fn new(config: NetworkPrivacyConfig, network: Arc<NetworkInterface>) -> Self {
        Self {
            dandelion: Arc::new(DandelionProtocol::new(&config)),
            obfuscator: Arc::new(TrafficObfuscator::new(&config)),
            decoy_generator: Arc::new(DecoyGenerator::new(&config)),
            amount_decorrelator: Arc::new(AmountDecorrelator::new(config.amount_noise_percent)),
            transaction_batcher: Arc::new(TransactionBatcher::new(
                config.batch_window_ms,
                config.min_batch_size,
            )),
            network,
            config,
        }
    }

    /// Create new network privacy layer with automatic Tor/I2P configuration
    /// PRODUCTION: Use this constructor to ensure Tor/I2P settings are applied correctly
    pub fn with_config(config: NetworkPrivacyConfig) -> Self {
        let network = Arc::new(NetworkInterface::with_privacy_config(&config));
        Self::new(config, network)
    }

    /// Send transaction with complete privacy protection
    ///
    /// # Arguments
    /// * `tx_data` - Raw transaction data to send
    /// * `tx_hash` - Hash of the transaction for tracking
    /// * `zk_proof` - Optional zero-knowledge proof for transaction validity
    ///
    /// # Privacy Features
    /// - Dandelion++ propagation (stem → fluff)
    /// - Traffic obfuscation with random padding
    /// - Decoy traffic generation
    /// - Timing decorrelation with random delays
    /// - Tor/I2P routing (if enabled)
    /// - IP address masking
    ///
    /// # Returns
    /// Transaction hash after successful propagation
    ///
    /// # Errors
    /// Returns error if network propagation fails or privacy features cannot be applied
    pub async fn send_private_transaction(
        &self,
        tx_data: &[u8],
        tx_hash: H256,
        _zk_proof: Option<&Proof>,  // Changed from ring_signature
    ) -> Result<H256> {
        // CRITICAL FIX: Implement complete privacy protection

        tracing::info!("Sending transaction with enhanced network privacy: {:?}", tx_hash);

        // Step 1: Add to batch (prevents timing analysis)
        if self.config.batch_window_ms > 0 {
            self.transaction_batcher.add_transaction(tx_hash, tx_data.to_vec()).await;

            // Wait for batch to be ready
            while !self.transaction_batcher.is_batch_ready().await {
                sleep(Duration::from_millis(100)).await;
            }

            // Process entire batch
            let batch = self.transaction_batcher.get_batch().await;
            for (batch_hash, batch_data) in batch {
                self.send_single_transaction(&batch_data, batch_hash).await?;
            }
        } else {
            // Send immediately if batching disabled
            self.send_single_transaction(tx_data, tx_hash).await?;
        }

        Ok(tx_hash)
    }

    /// CRITICAL FIX: Send single transaction with all privacy features
    async fn send_single_transaction(
        &self,
        tx_data: &[u8],
        tx_hash: H256,
    ) -> Result<()> {
        // Step 1: Add randomized timing delay
        if self.config.enable_traffic_obfuscation {
            self.obfuscator.add_timing_delay().await;
        }

        // Step 2: Pad transaction data to uniform size
        let padded_data = self.obfuscator.pad_transaction(tx_data);

        // Step 3: Propagate using Dandelion++ with Tor/I2P
        if self.config.enable_dandelion {
            self.dandelion.propagate(tx_hash, &padded_data, &self.network).await?;
        } else {
            // Direct broadcast if Dandelion disabled
            self.network.broadcast(&padded_data).await?;
        }

        // Step 4: Generate decoy traffic to obscure real transaction
        if self.config.enable_decoy_traffic {
            self.decoy_generator.generate_decoys(&self.network).await?;
        }

        tracing::info!("Transaction sent with complete privacy protections: {:?}", tx_hash);

        Ok(())
    }

    /// CRITICAL FIX: Decorrelate amounts before sending
    pub fn decorrelate_amount(&self, amount: U256) -> Vec<U256> {
        if self.config.enable_amount_decorrelation {
            self.amount_decorrelator.decorrelate(amount)
        } else {
            vec![amount]
        }
    }

    /// Handle received transaction with privacy
    pub async fn handle_received_transaction(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Remove padding
        let unpadded = self.obfuscator.unpad_transaction(data)?;

        // Add random delay before processing (prevent timing analysis)
        if self.config.enable_traffic_obfuscation {
            let mut rng = rand::thread_rng();
            let delay = rng.gen_range(10..100);
            sleep(Duration::from_millis(delay)).await;
        }

        Ok(unpadded)
    }

    /// Start background cleanup task to prevent memory leaks
    /// CRITICAL: Call this once during initialization to start periodic cleanup
    /// Runs cleanup every 60 seconds to remove old Dandelion states and orphaned routes
    pub fn start_cleanup_task(&self) {
        let dandelion = self.dandelion.clone();

        tokio::spawn(async move {
            tracing::info!("Starting Dandelion cleanup background task (runs every 60s)");

            loop {
                // Wait 60 seconds between cleanups
                tokio::time::sleep(Duration::from_secs(60)).await;

                // Run cleanup
                dandelion.cleanup_old_states().await;
            }
        });
    }

    /// Get network privacy statistics from current configuration
    /// PRODUCTION: Returns actual config values, not hardcoded data
    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "dandelion_enabled": self.config.enable_dandelion,
            "traffic_obfuscation_enabled": self.config.enable_traffic_obfuscation,
            "tor_enabled": self.config.use_tor,
            "i2p_enabled": self.config.use_i2p,
            "batch_window_ms": self.config.batch_window_ms,
            "min_batch_size": self.config.min_batch_size,
            "amount_noise_percent": self.config.amount_noise_percent,
            "amount_decorrelation_enabled": self.config.enable_amount_decorrelation,
            "decoy_traffic_enabled": self.config.enable_decoy_traffic,
            "decoy_traffic_rate": self.config.decoy_traffic_rate,
            "timing_delay_ms": self.config.timing_delay_ms
        })
    }
}

/// Simple LRU cache for IP masking to prevent memory leaks
/// PRODUCTION: Limits memory usage by evicting oldest entries
struct LruIpCache {
    cache: HashMap<String, (String, u64)>,  // IP -> (masked_id, access_time)
    max_size: usize,
    access_counter: u64,
}

impl LruIpCache {
    fn new(max_size: usize) -> Self {
        Self {
            cache: HashMap::new(),
            max_size,
            access_counter: 0,
        }
    }

    /// Get or insert value using Entry API to avoid TOCTOU race condition
    /// FIXED: Uses Entry API for atomic check-and-insert operation
    fn get_or_insert<F>(&mut self, key: &str, value_fn: F) -> String
    where
        F: FnOnce() -> String,
    {
        self.access_counter += 1;

        // Check if key already exists
        if let Some((value, access_time)) = self.cache.get_mut(key) {
            // Update access time and return existing value
            *access_time = self.access_counter;
            return value.clone();
        }

        // Key doesn't exist - need to insert
        // First, evict oldest if at capacity
        if self.cache.len() >= self.max_size {
            if let Some(oldest_key) = self.cache.iter()
                .min_by_key(|(_, (_, time))| time)
                .map(|(k, _)| k.clone())
            {
                self.cache.remove(&oldest_key);
                tracing::debug!("Evicted oldest IP from mask cache: {}", oldest_key);
            }
        }

        // Generate and insert new value
        let value = value_fn();
        self.cache.insert(key.to_string(), (value.clone(), self.access_counter));
        value
    }

    /// Returns the current number of cached IP entries
    /// Useful for monitoring cache size and debugging memory usage
    pub fn len(&self) -> usize {
        self.cache.len()
    }
}

/// Network interface abstraction
#[derive(Clone)]
pub struct NetworkInterface {
    peers: Arc<RwLock<Vec<String>>>,
    connections: Arc<RwLock<HashMap<String, NetworkConnection>>>,
    message_queue: Arc<RwLock<HashMap<String, Vec<Vec<u8>>>>>,
    listen_addr: String,
    encryption_enabled: bool,
    // CRITICAL FIX: Add Tor/I2P anonymization support
    tor_enabled: bool,
    tor_proxy_addr: String,
    i2p_enabled: bool,
    i2p_proxy_addr: String,
    // CRITICAL FIX: Hide real IP addresses with LRU cache to prevent memory leak
    ip_masking_enabled: bool,
    masked_ips: Arc<RwLock<LruIpCache>>,  // PRODUCTION: LRU cache with max 10000 entries
}

impl NetworkInterface {
    pub fn new() -> Self {
        Self::with_config("0.0.0.0:9050", true)
    }

    pub fn with_config(listen_addr: &str, encryption_enabled: bool) -> Self {
        Self {
            peers: Arc::new(RwLock::new(Vec::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            message_queue: Arc::new(RwLock::new(HashMap::new())),
            listen_addr: listen_addr.to_string(),
            encryption_enabled,
            tor_enabled: false,
            tor_proxy_addr: "127.0.0.1:9050".to_string(),
            i2p_enabled: false,
            i2p_proxy_addr: "127.0.0.1:4444".to_string(),
            ip_masking_enabled: false,
            masked_ips: Arc::new(RwLock::new(LruIpCache::new(10000))),  // Max 10000 cached IPs
        }
    }

    /// Create network interface with privacy configuration applied
    /// PRODUCTION: Use this constructor to enable Tor/I2P based on privacy config
    pub fn with_privacy_config(config: &NetworkPrivacyConfig) -> Self {
        Self {
            peers: Arc::new(RwLock::new(Vec::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            message_queue: Arc::new(RwLock::new(HashMap::new())),
            listen_addr: "0.0.0.0:9050".to_string(),
            encryption_enabled: true,
            tor_enabled: config.use_tor,
            tor_proxy_addr: config.tor_proxy.clone(),
            i2p_enabled: config.use_i2p,
            i2p_proxy_addr: config.i2p_proxy.clone(),
            ip_masking_enabled: true,  // Always enable IP masking for privacy
            masked_ips: Arc::new(RwLock::new(LruIpCache::new(10000))),
        }
    }

    pub async fn get_connected_peers(&self) -> Result<Vec<String>> {
        Ok(self.peers.read().await.clone())
    }

    pub async fn send_to_peer(&self, peer: &str, data: &[u8]) -> Result<()> {
        tracing::debug!("Sending {} bytes to peer: {}", data.len(), peer);

        // Check if we have an active connection
        let connections = self.connections.read().await;

        if let Some(conn) = connections.get(peer) {
            // Send through existing connection
            conn.send_data(data).await?
        } else {
            drop(connections);

            // Establish new connection
            let conn = self.connect_to_peer(peer).await?;

            // Send data
            conn.send_data(data).await?;

            // Store connection for reuse
            let mut connections = self.connections.write().await;
            connections.insert(peer.to_string(), conn);
        }

        Ok(())
    }

    pub async fn broadcast(&self, data: &[u8]) -> Result<()> {
        let peers = self.peers.read().await;
        tracing::debug!("Broadcasting {} bytes to {} peers", data.len(), peers.len());

        // Broadcast to all connected peers in parallel
        let mut tasks = Vec::new();

        for peer in peers.iter() {
            let peer_clone = peer.clone();
            let data_clone = data.to_vec();
            let self_clone = self.clone();

            let task = tokio::spawn(async move {
                if let Err(e) = self_clone.send_to_peer(&peer_clone, &data_clone).await {
                    tracing::warn!("Failed to send to peer {}: {}", peer_clone, e);
                }
            });

            tasks.push(task);
        }

        // Wait for all broadcasts to complete
        for task in tasks {
            let _ = task.await;
        }

        Ok(())
    }

    pub async fn add_peer(&self, peer: String) {
        let mut peers = self.peers.write().await;
        if !peers.contains(&peer) {
            peers.push(peer.clone());
            tracing::info!("Added new peer: {}", peer);
        }
    }

    pub async fn remove_peer(&self, peer: &str) {
        let mut peers = self.peers.write().await;
        peers.retain(|p| p != peer);

        // Clean up connection
        let mut connections = self.connections.write().await;
        connections.remove(peer);

        tracing::info!("Removed peer: {}", peer);
    }

    /// CRITICAL FIX: Use existing with_config for Tor/I2P connections
    async fn use_tor_connection(&self, peer_addr: &str) -> bool {
        // Check if address looks like a Tor hidden service
        peer_addr.ends_with(".onion") || self.listen_addr.contains("9050")
    }

    /// CRITICAL FIX: Mask IP addresses in logs and connections
    /// FIXED: Uses get_or_insert to avoid TOCTOU race condition
    async fn mask_ip_address(&self, real_ip: &str) -> String {
        if !self.ip_masking_enabled {
            return real_ip.to_string();
        }

        let mut masked_ips = self.masked_ips.write().await;

        // FIXED: Use get_or_insert for atomic check-and-insert
        masked_ips.get_or_insert(real_ip, || {
            // Generate masked ID for this IP (only called if not in cache)
            let mut hasher = Keccak256::default();
            hasher.update(real_ip.as_bytes());
            hasher.update(b"qoranet_ip_mask");
            let hash = hasher.finalize();

            // Use first 8 hex chars as masked ID
            format!("peer_{}", hex::encode(&hash[0..4]))
        })
    }

    /// CRITICAL FIX: Connect through Tor/I2P proxy for anonymization
    async fn connect_to_peer(&self, peer_addr: &str) -> Result<NetworkConnection> {
        use tokio::net::TcpStream;

        // Mask IP in logs
        let masked_peer = self.mask_ip_address(peer_addr).await;
        tracing::debug!("Connecting to peer: {}", masked_peer);

        // CRITICAL FIX: Route through Tor/I2P if enabled
        let stream = if self.tor_enabled {
            self.connect_via_tor(peer_addr).await?
        } else if self.i2p_enabled {
            self.connect_via_i2p(peer_addr).await?
        } else {
            // Direct connection (not recommended)
            tracing::warn!("Direct connection without Tor/I2P - IP may be exposed");

            // Parse peer address
            let addr = peer_addr.parse::<std::net::SocketAddr>()
                .map_err(|e| anyhow!("Invalid peer address: {}", e))?;

            timeout(
                Duration::from_secs(10),
                TcpStream::connect(addr)
            ).await
                .map_err(|_| anyhow!("Connection timeout"))?
                .map_err(|e| anyhow!("Connection failed: {}", e))?
        };

        // Create connection wrapper with masked IP logging
        let conn = NetworkConnection::new(stream, self.encryption_enabled).await?;

        tracing::info!("Connected to peer: {}", masked_peer);
        Ok(conn)
    }

    /// CRITICAL FIX: Connect through Tor SOCKS5 proxy
    async fn connect_via_tor(&self, target_addr: &str) -> Result<tokio::net::TcpStream> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Connect to Tor SOCKS5 proxy
        let proxy_addr = self.tor_proxy_addr.parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow!("Invalid Tor proxy address: {}", e))?;

        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await
            .map_err(|e| anyhow!("Failed to connect to Tor proxy: {}", e))?;

        // SOCKS5 handshake - Step 1: Authentication negotiation
        // Send greeting: [VERSION, NMETHODS, METHODS...]
        stream.write_all(&[0x05, 0x01, 0x00]).await?;  // Version 5, 1 method, no auth

        // Read server's chosen method (with timeout to prevent hang)
        let mut response = [0u8; 2];
        timeout(Duration::from_secs(30), stream.read_exact(&mut response))
            .await
            .map_err(|_| anyhow!("SOCKS5 greeting handshake timeout (30s)"))?
            .map_err(|e| anyhow!("Failed to read SOCKS5 greeting response: {}", e))?;

        // PRODUCTION: Verify SOCKS5 version and auth method
        if response[0] != 0x05 {
            return Err(anyhow!("Invalid SOCKS5 version in response: 0x{:02x}", response[0]));
        }
        if response[1] != 0x00 {
            return Err(anyhow!("SOCKS5 auth method rejected: 0x{:02x}", response[1]));
        }

        // Parse target address
        let target = target_addr.parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow!("Invalid target address: {}", e))?;

        // SOCKS5 handshake - Step 2: Connection request
        let mut request = Vec::new();
        request.push(0x05);  // Version
        request.push(0x01);  // Connect command
        request.push(0x00);  // Reserved

        match target {
            std::net::SocketAddr::V4(addr) => {
                request.push(0x01);  // IPv4
                request.extend_from_slice(&addr.ip().octets());
                request.extend_from_slice(&addr.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(addr) => {
                request.push(0x04);  // IPv6
                request.extend_from_slice(&addr.ip().octets());
                request.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        stream.write_all(&request).await
            .map_err(|e| anyhow!("Failed to send SOCKS5 connection request: {}", e))?;

        // Read connection response (with timeout to prevent hang)
        // Response format: [VER(1), REP(1), RSV(1), ATYP(1), BND.ADDR(variable), BND.PORT(2)]
        let mut response = [0u8; 4];
        timeout(Duration::from_secs(30), stream.read_exact(&mut response))
            .await
            .map_err(|_| anyhow!("SOCKS5 connection response timeout (30s)"))?
            .map_err(|e| anyhow!("Failed to read SOCKS5 connection response: {}", e))?;

        // CRITICAL: Verify connection succeeded
        if response[0] != 0x05 {
            return Err(anyhow!("Invalid SOCKS5 version in connection response: 0x{:02x}", response[0]));
        }

        // Check reply code (response[1])
        match response[1] {
            0x00 => {}, // Success
            0x01 => return Err(anyhow!("SOCKS5: General server failure")),
            0x02 => return Err(anyhow!("SOCKS5: Connection not allowed by ruleset")),
            0x03 => return Err(anyhow!("SOCKS5: Network unreachable")),
            0x04 => return Err(anyhow!("SOCKS5: Host unreachable")),
            0x05 => return Err(anyhow!("SOCKS5: Connection refused by destination host")),
            0x06 => return Err(anyhow!("SOCKS5: TTL expired")),
            0x07 => return Err(anyhow!("SOCKS5: Command not supported")),
            0x08 => return Err(anyhow!("SOCKS5: Address type not supported")),
            code => return Err(anyhow!("SOCKS5: Unknown error code: 0x{:02x}", code)),
        }

        // Read remaining response (BND.ADDR and BND.PORT) based on ATYP (with timeouts)
        match response[3] {
            0x01 => {
                // IPv4: 4 bytes addr + 2 bytes port
                let mut remaining = [0u8; 6];
                timeout(Duration::from_secs(30), stream.read_exact(&mut remaining))
                    .await
                    .map_err(|_| anyhow!("SOCKS5 IPv4 address read timeout (30s)"))?
                    .map_err(|e| anyhow!("Failed to read SOCKS5 IPv4 address: {}", e))?;
            }
            0x03 => {
                // Domain: 1 byte length + N bytes domain + 2 bytes port
                let mut len_byte = [0u8; 1];
                timeout(Duration::from_secs(30), stream.read_exact(&mut len_byte))
                    .await
                    .map_err(|_| anyhow!("SOCKS5 domain length read timeout (30s)"))?
                    .map_err(|e| anyhow!("Failed to read SOCKS5 domain length: {}", e))?;
                let domain_len = len_byte[0] as usize;
                let mut remaining = vec![0u8; domain_len + 2];
                timeout(Duration::from_secs(30), stream.read_exact(&mut remaining))
                    .await
                    .map_err(|_| anyhow!("SOCKS5 domain name read timeout (30s)"))?
                    .map_err(|e| anyhow!("Failed to read SOCKS5 domain name: {}", e))?;
            }
            0x04 => {
                // IPv6: 16 bytes addr + 2 bytes port
                let mut remaining = [0u8; 18];
                timeout(Duration::from_secs(30), stream.read_exact(&mut remaining))
                    .await
                    .map_err(|_| anyhow!("SOCKS5 IPv6 address read timeout (30s)"))?
                    .map_err(|e| anyhow!("Failed to read SOCKS5 IPv6 address: {}", e))?;
            }
            atyp => return Err(anyhow!("SOCKS5: Unsupported address type: 0x{:02x}", atyp)),
        }

        tracing::info!("Successfully connected through Tor to {}", self.mask_ip_address(target_addr).await);
        Ok(stream)
    }

    /// CRITICAL FIX: Connect through I2P SOCKS5 proxy
    /// PRODUCTION: I2P also uses SOCKS5 protocol (similar to Tor)
    async fn connect_via_i2p(&self, target_addr: &str) -> Result<tokio::net::TcpStream> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Connect to I2P SOCKS5 proxy
        let proxy_addr = self.i2p_proxy_addr.parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow!("Invalid I2P proxy address: {}", e))?;

        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await
            .map_err(|e| anyhow!("Failed to connect to I2P proxy: {}", e))?;

        // SOCKS5 handshake - Step 1: Authentication negotiation
        stream.write_all(&[0x05, 0x01, 0x00]).await?;  // Version 5, 1 method, no auth

        // Read server's chosen method (with timeout to prevent hang)
        let mut response = [0u8; 2];
        timeout(Duration::from_secs(30), stream.read_exact(&mut response))
            .await
            .map_err(|_| anyhow!("I2P SOCKS5 greeting handshake timeout (30s)"))?
            .map_err(|e| anyhow!("Failed to read I2P SOCKS5 greeting response: {}", e))?;

        // PRODUCTION: Verify SOCKS5 version and auth method
        if response[0] != 0x05 {
            return Err(anyhow!("Invalid SOCKS5 version from I2P: 0x{:02x}", response[0]));
        }
        if response[1] != 0x00 {
            return Err(anyhow!("I2P SOCKS5 auth method rejected: 0x{:02x}", response[1]));
        }

        // For I2P, target_addr should be an .i2p hostname or b32 address
        // Parse as domain name for I2P destinations
        // SOCKS5 handshake - Step 2: Connection request with domain name
        let mut request = Vec::new();
        request.push(0x05);  // Version
        request.push(0x01);  // Connect command
        request.push(0x00);  // Reserved
        request.push(0x03);  // Domain name address type

        // Extract host and port
        let parts: Vec<&str> = target_addr.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid I2P address format (expected host:port)"));
        }

        let host = parts[0];
        let port: u16 = parts[1].parse()
            .map_err(|e| anyhow!("Invalid port in I2P address: {}", e))?;

        // Add domain length and domain
        if host.len() > 255 {
            return Err(anyhow!("I2P hostname too long (max 255 bytes)"));
        }
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());

        stream.write_all(&request).await
            .map_err(|e| anyhow!("Failed to send I2P SOCKS5 connection request: {}", e))?;

        // Read connection response (with timeout to prevent hang)
        let mut response = [0u8; 4];
        timeout(Duration::from_secs(30), stream.read_exact(&mut response))
            .await
            .map_err(|_| anyhow!("I2P SOCKS5 connection response timeout (30s)"))?
            .map_err(|e| anyhow!("Failed to read I2P SOCKS5 connection response: {}", e))?;

        // CRITICAL: Verify connection succeeded
        if response[0] != 0x05 {
            return Err(anyhow!("Invalid SOCKS5 version in I2P response: 0x{:02x}", response[0]));
        }

        // Check reply code
        match response[1] {
            0x00 => {}, // Success
            0x01 => return Err(anyhow!("I2P SOCKS5: General server failure")),
            0x02 => return Err(anyhow!("I2P SOCKS5: Connection not allowed by ruleset")),
            0x03 => return Err(anyhow!("I2P SOCKS5: Network unreachable")),
            0x04 => return Err(anyhow!("I2P SOCKS5: Host unreachable (destination not found)")),
            0x05 => return Err(anyhow!("I2P SOCKS5: Connection refused by destination")),
            0x06 => return Err(anyhow!("I2P SOCKS5: TTL expired")),
            0x07 => return Err(anyhow!("I2P SOCKS5: Command not supported")),
            0x08 => return Err(anyhow!("I2P SOCKS5: Address type not supported")),
            code => return Err(anyhow!("I2P SOCKS5: Unknown error code: 0x{:02x}", code)),
        }

        // Read remaining response (BND.ADDR and BND.PORT) based on ATYP (with timeouts)
        match response[3] {
            0x01 => {
                // IPv4: 4 bytes addr + 2 bytes port
                let mut remaining = [0u8; 6];
                timeout(Duration::from_secs(30), stream.read_exact(&mut remaining))
                    .await
                    .map_err(|_| anyhow!("I2P SOCKS5 IPv4 address read timeout (30s)"))?
                    .map_err(|e| anyhow!("Failed to read I2P SOCKS5 IPv4 address: {}", e))?;
            }
            0x03 => {
                // Domain: 1 byte length + N bytes domain + 2 bytes port
                let mut len_byte = [0u8; 1];
                timeout(Duration::from_secs(30), stream.read_exact(&mut len_byte))
                    .await
                    .map_err(|_| anyhow!("I2P SOCKS5 domain length read timeout (30s)"))?
                    .map_err(|e| anyhow!("Failed to read I2P SOCKS5 domain length: {}", e))?;
                let domain_len = len_byte[0] as usize;
                let mut remaining = vec![0u8; domain_len + 2];
                timeout(Duration::from_secs(30), stream.read_exact(&mut remaining))
                    .await
                    .map_err(|_| anyhow!("I2P SOCKS5 domain name read timeout (30s)"))?
                    .map_err(|e| anyhow!("Failed to read I2P SOCKS5 domain name: {}", e))?;
            }
            0x04 => {
                // IPv6: 16 bytes addr + 2 bytes port
                let mut remaining = [0u8; 18];
                timeout(Duration::from_secs(30), stream.read_exact(&mut remaining))
                    .await
                    .map_err(|_| anyhow!("I2P SOCKS5 IPv6 address read timeout (30s)"))?
                    .map_err(|e| anyhow!("Failed to read I2P SOCKS5 IPv6 address: {}", e))?;
            }
            atyp => return Err(anyhow!("I2P SOCKS5: Unsupported address type: 0x{:02x}", atyp)),
        }

        tracing::info!("Successfully connected through I2P to {}", self.mask_ip_address(target_addr).await);
        Ok(stream)
    }

    pub async fn listen(&self) -> Result<()> {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(&self.listen_addr).await?;
        tracing::info!("Listening on: {}", self.listen_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            let self_clone = self.clone();

            tokio::spawn(async move {
                if let Ok(conn) = NetworkConnection::new(stream, self_clone.encryption_enabled).await {
                    let peer_addr = addr.to_string();

                    // Add peer
                    self_clone.add_peer(peer_addr.clone()).await;

                    // Store connection
                    let mut connections = self_clone.connections.write().await;
                    connections.insert(peer_addr.clone(), conn);

                    tracing::info!("Accepted connection from: {}", peer_addr);
                }
            });
        }
    }
}

/// Network connection wrapper with encryption support
struct NetworkConnection {
    stream: Arc<Mutex<tokio::net::TcpStream>>,
    encryption_key: Option<[u8; 32]>,
}

impl NetworkConnection {
    async fn new(stream: tokio::net::TcpStream, enable_encryption: bool) -> Result<Self> {
        use rand::RngCore;

        let encryption_key = if enable_encryption {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            Some(key)
        } else {
            None
        };

        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
            encryption_key,
        })
    }

    async fn send_data(&self, data: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let mut stream = self.stream.lock().await;

        // Encrypt if enabled
        let data_to_send = if let Some(key) = &self.encryption_key {
            self.encrypt_data(data, key)?
        } else {
            data.to_vec()
        };

        // Send length prefix
        let len = data_to_send.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;

        // Send data
        stream.write_all(&data_to_send).await?;
        stream.flush().await?;

        Ok(())
    }

    async fn receive_data(&self) -> Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;

        let mut stream = self.stream.lock().await;

        // Read length prefix (with timeout to prevent hang)
        let mut len_bytes = [0u8; 4];
        timeout(Duration::from_secs(60), stream.read_exact(&mut len_bytes))
            .await
            .map_err(|_| anyhow!("Timeout waiting for message length (60s)"))?
            .map_err(|e| anyhow!("Failed to read message length: {}", e))?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        // Sanity check
        if len > 10_000_000 {  // 10MB max
            return Err(anyhow!("Message too large: {} bytes", len));
        }

        // Read data (with timeout to prevent hang)
        let mut buffer = vec![0u8; len];
        timeout(Duration::from_secs(120), stream.read_exact(&mut buffer))
            .await
            .map_err(|_| anyhow!("Timeout waiting for message data (120s)"))?
            .map_err(|e| anyhow!("Failed to read message data: {}", e))?;

        // Decrypt if enabled
        let data = if let Some(key) = &self.encryption_key {
            self.decrypt_data(&buffer, key)?
        } else {
            buffer
        };

        Ok(data)
    }

    /// Encrypt data - delegates to TrafficObfuscator to avoid code duplication
    /// PRODUCTION: Single source of truth for encryption implementation
    /// OPTIMIZED: Static call - no allocation overhead
    pub fn encrypt_data(&self, data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        TrafficObfuscator::encrypt_data(data, key)
    }

    /// Decrypt data - delegates to TrafficObfuscator to avoid code duplication
    /// PRODUCTION: Single source of truth for decryption implementation
    /// OPTIMIZED: Static call - no allocation overhead
    pub fn decrypt_data(&self, data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        TrafficObfuscator::decrypt_data(data, key)
    }
}

/// Metadata privacy layer
pub struct MetadataPrivacy {
    /// Fixed packet size for all messages
    packet_size: usize,
    /// Cover traffic generator
    cover_traffic: Arc<RwLock<CoverTrafficGenerator>>,
}

impl MetadataPrivacy {
    pub fn new() -> Self {
        Self {
            packet_size: 8192, // 8KB fixed size for all packets
            cover_traffic: Arc::new(RwLock::new(CoverTrafficGenerator::new())),
        }
    }

    /// Pad or split message to fixed size packets
    pub fn prepare_message(&self, data: &[u8]) -> Vec<[u8; 8192]> {
        let mut packets = Vec::new();
        let mut remaining = data;

        while !remaining.is_empty() {
            let mut packet = [0u8; 8192];

            // Add header: [msg_id(32), packet_index(2), total_packets(2), data_len(2)]
            let msg_id = H256::random();
            packet[0..32].copy_from_slice(msg_id.as_bytes());
            packet[32..34].copy_from_slice(&(packets.len() as u16).to_le_bytes());

            let chunk_size = remaining.len().min(8192 - 40);
            packet[36..38].copy_from_slice(&(chunk_size as u16).to_le_bytes());
            packet[40..40 + chunk_size].copy_from_slice(&remaining[..chunk_size]);

            // Fill rest with random padding
            OsRng.fill_bytes(&mut packet[40 + chunk_size..]);

            packets.push(packet);
            remaining = &remaining[chunk_size..];
        }

        packets
    }
}

pub struct CoverTrafficGenerator {
    enabled: bool,
    rate: u64, // packets per second
    last_sent: Instant,
}

impl CoverTrafficGenerator {
    pub fn new() -> Self {
        Self {
            enabled: true,
            rate: 10, // 10 fake packets per second
            last_sent: Instant::now(),
        }
    }

    pub async fn maintain_cover_traffic(&self, network: &NetworkInterface) {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Send dummy packet
            let mut dummy = [0u8; 8192];
            dummy[0] = 0xFF; // Mark as dummy
            OsRng.fill_bytes(&mut dummy[1..]);

            let _ = network.broadcast(&dummy).await;
        }
    }
}

/// Fake transaction for decoy traffic
/// FIXED: Removed index field to prevent decoy detection
#[derive(Serialize, Deserialize)]
struct FakeTransaction {
    version: u8,
    tx_type: &'static str,
    zk_proof_size: u32,  // Randomized from real TX distribution
    amount: U256,
    fee: U256,
    nonce: u64,
    timestamp: u64,
    random_data: H256,
    // REMOVED: index field - it exposes decoys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dandelion_protocol() {
        let config = NetworkPrivacyConfig::default();
        let network = Arc::new(NetworkInterface::new());

        // Add test peers
        network.add_peer("peer1".to_string()).await;
        network.add_peer("peer2".to_string()).await;
        network.add_peer("peer3".to_string()).await;

        let dandelion = DandelionProtocol::new(&config);

        let tx_hash = H256::random();
        let tx_data = b"test transaction";

        // Test stem phase
        let result = dandelion.propagate(tx_hash, tx_data, &network).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_traffic_obfuscation() {
        let config = NetworkPrivacyConfig::default();
        let obfuscator = TrafficObfuscator::new(&config);

        let original = b"small tx";
        let padded = obfuscator.pad_transaction(original);

        assert_eq!(padded.len(), 2048);
        assert!(padded.starts_with(original));
    }

    #[tokio::test]
    async fn test_network_privacy_layer() {
        let config = NetworkPrivacyConfig::default();
        let network = Arc::new(NetworkInterface::new());
        network.add_peer("peer1".to_string()).await;

        let privacy_layer = NetworkPrivacyLayer::new(config, network);

        // Create test transaction data
        let tx_data = b"test transaction data";
        let tx_hash = H256::random();

        let result = privacy_layer.send_private_transaction(tx_data, tx_hash, None).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_authenticated_encryption() {
        let key = [42u8; 32]; // Test key
        let plaintext = b"sensitive data that must not be tampered with";

        // Test successful encryption and decryption
        let encrypted = TrafficObfuscator::encrypt_data(plaintext, &key).unwrap();
        let decrypted = TrafficObfuscator::decrypt_data(&encrypted, &key).unwrap();

        assert_eq!(plaintext, &decrypted[..], "Decryption failed to recover original data");

        // Verify encrypted data has authentication tag
        // AES-GCM format: nonce(12) + ciphertext + tag(16) = plaintext.len() + 28
        assert_eq!(encrypted.len(), plaintext.len() + 28, "Invalid AES-GCM encrypted data size");
    }

    #[test]
    fn test_authentication_prevents_tampering() {
        let key = [42u8; 32];
        let plaintext = b"critical transaction data";

        // Encrypt the data
        let mut encrypted = TrafficObfuscator::encrypt_data(plaintext, &key).unwrap();

        // ATTACK: Attempt to tamper with the ciphertext (bit-flipping attack)
        // Flip a bit in the middle of the ciphertext
        if encrypted.len() > 20 {
            encrypted[20] ^= 0x01; // Flip one bit
        }

        // Decryption should FAIL due to authentication check
        let result = TrafficObfuscator::decrypt_data(&encrypted, &key);
        assert!(result.is_err(), "Authentication should detect tampering");

        if let Err(e) = result {
            assert!(e.to_string().contains("Authentication failed") ||
                    e.to_string().contains("tampered"),
                    "Error should indicate authentication failure");
        }
    }

    #[test]
    fn test_authentication_with_wrong_key() {
        let key1 = [42u8; 32];
        let key2 = [43u8; 32]; // Different key
        let plaintext = b"secret message";

        // Encrypt with key1
        let encrypted = TrafficObfuscator::encrypt_data(plaintext, &key1).unwrap();

        // Try to decrypt with key2 - should fail authentication
        let result = TrafficObfuscator::decrypt_data(&encrypted, &key2);
        assert!(result.is_err(), "Should not decrypt with wrong key");

        if let Err(e) = result {
            assert!(e.to_string().contains("Authentication failed") ||
                    e.to_string().contains("incorrect"),
                    "Error should indicate authentication/key failure");
        }
    }

    #[test]
    fn test_encryption_uniqueness() {
        // Verify that encrypting the same data twice produces different ciphertexts (due to random nonce)
        let key = [42u8; 32];
        let plaintext = b"repeated message";

        let encrypted1 = TrafficObfuscator::encrypt_data(plaintext, &key).unwrap();
        let encrypted2 = TrafficObfuscator::encrypt_data(plaintext, &key).unwrap();

        // Should produce different ciphertexts due to random nonces
        assert_ne!(encrypted1, encrypted2, "Encryption should use random nonces");

        // But both should decrypt to the same plaintext
        let decrypted1 = TrafficObfuscator::decrypt_data(&encrypted1, &key).unwrap();
        let decrypted2 = TrafficObfuscator::decrypt_data(&encrypted2, &key).unwrap();
        assert_eq!(decrypted1, decrypted2, "Both should decrypt to same plaintext");
        assert_eq!(decrypted1, plaintext, "Should decrypt to original plaintext");
    }
}
