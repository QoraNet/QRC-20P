# Rust-to-Rust FFI Redesign

## Current Issues with Go FFI Approach

The existing FFI was designed for **Go interop** and has unnecessary complexity for Rust-to-Rust:

### ❌ Go FFI Patterns (Remove)
```rust
// Complex C ABI exports
#[no_mangle]
pub extern "C" fn privacy_init() -> *mut c_void { ... }

// CString conversions
let c_str = CStr::from_ptr(token_address_ptr).to_str().unwrap();

// Manual memory management
Box::into_raw(Box::new(result))

// Magic number validation
const PRIVACY_HANDLE_MAGIC: u64 = 0xDEADBEEF_CAFEBABE;

// Global state (❌ BLOCKCHAIN HANDLES THIS)
pub(crate) global_state: Arc<RwLock<GlobalState>>,
pub(crate) universal_switch: Arc<UniversalSwitch>,
pub(crate) token_factory: Arc<TokenFactory>,
```

### ✅ Rust-to-Rust FFI Patterns (Use)
```rust
// Native Rust public API
pub fn privacy_init() -> Result<PrivacySystem, PrivacyError> { ... }

// Native Rust types (no conversion)
pub fn compute_commitment(secret: H256, amount: U256, blinding: H256) -> Result<H256, PrivacyError>

// Safe memory (Rust ownership)
pub struct PrivacySystem { ... }

// No magic numbers needed (Rust type safety)

// NO global state (pallet handles storage)
```

---

## New Stateless API Design

### Core Principle: Separation of Concerns

```
┌─────────────────────────────────────────────────────┐
│ Substrate Pallet (Frontier)                         │
│  - Manages ALL state (commitments, nullifiers, etc) │
│  - Transaction logic                                │
│  - Storage                                          │
└────────────────┬────────────────────────────────────┘
                 │
                 │ Calls (native Rust)
                 ▼
┌─────────────────────────────────────────────────────┐
│ Privacy-Lib (Stateless)                             │
│  - Pure cryptographic functions                     │
│  - NO state management                              │
│  - NO pools, factories, switches                    │
└─────────────────────────────────────────────────────┘
```

### API Structure

#### 1. Proof System Handle (Cached Keys Only)

```rust
/// Minimal handle - ONLY holds cached proving/verifying keys
pub struct PrivacySystem {
    proof_system: Arc<ProductionProofSystem>,
}

impl PrivacySystem {
    /// Initialize proof system (loads KZG parameters)
    /// Call once, reuse handle for all operations
    pub fn new(k: u32, lookup_bits: u8) -> Result<Self, PrivacyError> {
        let proof_system = ProductionProofSystem::new(k, lookup_bits)?;
        Ok(Self {
            proof_system: Arc::new(proof_system),
        })
    }
}
```

#### 2. Stateless Hash Functions

```rust
/// Poseidon hash (ZK-friendly)
pub fn poseidon_hash(left: H256, right: H256) -> H256 {
    use crate::crypto::poseidon::poseidon_hash_internal;
    poseidon_hash_internal(&[left, right])
}

/// Compute commitment: Poseidon(secret, amount, blinding)
pub fn compute_commitment(
    secret: H256,
    amount: U256,
    blinding: H256,
) -> Result<H256, PrivacyError> {
    // Pure function - no state access
    let commitment = poseidon_hash(
        secret,
        poseidon_hash(
            H256::from_uint(&amount),
            blinding,
        ),
    );
    Ok(commitment)
}

/// Compute nullifier: Poseidon(secret, leaf_index)
pub fn compute_nullifier(
    secret: H256,
    leaf_index: u32,
) -> Result<H256, PrivacyError> {
    let leaf_hash = H256::from_low_u64_be(leaf_index as u64);
    let nullifier = poseidon_hash(secret, leaf_hash);
    Ok(nullifier)
}
```

#### 3. Proof Generation (Stateless)

```rust
impl PrivacySystem {
    /// Generate ZK proof for single transfer
    /// Caller provides ALL witness data
    pub fn prove_transfer(
        &self,
        witness: TransferWitness,
    ) -> Result<TransferProof, PrivacyError> {
        // Use cached proof system (from handle)
        self.proof_system.prove(witness)
    }

    /// Verify ZK proof
    pub fn verify_transfer(
        &self,
        proof: &TransferProof,
        public_inputs: &TransferPublicInputs,
    ) -> Result<bool, PrivacyError> {
        self.proof_system.verify(proof, public_inputs)
    }
}

/// Witness data (all provided by caller, no state lookup)
#[derive(Debug, Clone)]
pub struct TransferWitness {
    pub secret: H256,
    pub amount: U256,
    pub blinding: H256,
    pub leaf_index: u32,
    pub merkle_path: Vec<H256>,
}

/// Public inputs (visible on blockchain)
#[derive(Debug, Clone)]
pub struct TransferPublicInputs {
    pub merkle_root: H256,
    pub nullifier: H256,
    pub commitment: H256,
}

/// Proof output
#[derive(Debug, Clone)]
pub struct TransferProof {
    pub proof_bytes: Vec<u8>,
}
```

#### 4. Stealth Addresses (Stateless)

```rust
/// Generate stealth address (ECDH)
/// No state - just crypto math
pub fn generate_stealth_address(
    receiver_pubkey: &PublicKey,
    ephemeral_secret: &SecretKey,
) -> Result<StealthAddress, PrivacyError> {
    use crate::stealth::stealth_addresses::generate_stealth_address_internal;
    generate_stealth_address_internal(receiver_pubkey, ephemeral_secret)
}

#[derive(Debug, Clone)]
pub struct StealthAddress {
    pub address: Address,
    pub ephemeral_pubkey: PublicKey,
}

/// Scan for stealth payments
/// Caller provides view key and ephemeral keys
pub fn scan_stealth_payment(
    view_key: &SecretKey,
    spend_pubkey: &PublicKey,
    ephemeral_pubkey: &PublicKey,
) -> Result<Option<SecretKey>, PrivacyError> {
    use crate::stealth::stealth_addresses::scan_stealth_payment_internal;
    scan_stealth_payment_internal(view_key, spend_pubkey, ephemeral_pubkey)
}
```

#### 5. Merkle Tree (Interface Only)

```rust
/// Merkle tree trait - pallet implements storage backend
pub trait MerkleStorage {
    fn get_leaf(&self, index: u32) -> Option<H256>;
    fn set_leaf(&mut self, index: u32, value: H256);
    fn get_node(&self, level: u8, index: u32) -> Option<H256>;
    fn set_node(&mut self, level: u8, index: u32, value: H256);
}

/// Merkle tree logic (stateless, uses trait)
pub struct MerkleTree<S: MerkleStorage> {
    storage: S,
    height: u8,
}

impl<S: MerkleStorage> MerkleTree<S> {
    pub fn new(storage: S, height: u8) -> Self {
        Self { storage, height }
    }

    pub fn insert(&mut self, index: u32, leaf: H256) -> Result<H256, PrivacyError> {
        // Compute new root using Poseidon hash
        // Update storage via trait
        // Return new root
        Ok(H256::zero()) // Simplified
    }

    pub fn get_proof(&self, index: u32) -> Result<Vec<H256>, PrivacyError> {
        // Generate Merkle proof path
        Ok(vec![])
    }
}
```

---

## File Structure

### New Clean Structure

```
privacy-lib/
├── src/
│   ├── lib.rs                 # Main public API exports
│   │
│   ├── api.rs                 # ✨ NEW: Stateless public API
│   │   ├── pub fn compute_commitment(...)
│   │   ├── pub fn compute_nullifier(...)
│   │   ├── pub fn poseidon_hash(...)
│   │   └── pub struct PrivacySystem { ... }
│   │
│   ├── crypto/
│   │   ├── poseidon.rs        # ✅ Pure hash functions
│   │   └── bn256_poseidon.rs
│   │
│   ├── circuits/
│   │   └── halo_circuits.rs   # ✅ ZK circuits (keep as-is)
│   │
│   ├── stealth/
│   │   └── stealth_addresses.rs # ✅ ECDH stealth addresses
│   │
│   ├── merkle/
│   │   └── merkle_tree.rs     # ✅ Merkle tree with trait
│   │
│   ├── nullifiers/
│   │   └── secure_privacy.rs  # ✅ Nullifier generation
│   │
│   ├── types.rs               # Common types
│   └── error.rs               # Error types
│
└── (REMOVE FFI modules - not needed for Rust-to-Rust)
    ❌ ffi.rs
    ❌ ffi_private_transfer.rs
    ❌ ffi_stealth_addresses.rs
    ❌ ffi_dual_token.rs
    ❌ ffi_universal_switch.rs
    ❌ ffi_network_privacy.rs
    ❌ ffi_amount_privacy.rs
    ❌ ffi_precompiles.rs
    ❌ ffi_validation.rs
```

---

## Usage from Frontier Off-Chain Worker

### Simple Direct Calls (No FFI Overhead!)

```rust
// In frontier/template/pallets/privacy/src/offchain.rs

use qoranet_privacy::{
    PrivacySystem,
    compute_commitment,
    compute_nullifier,
    TransferWitness,
    TransferPublicInputs,
};

fn generate_proof_for_request(request_id: u64) -> Result<(), Error> {
    // Initialize proof system (once, cache handle)
    let privacy_system = PrivacySystem::new(14, 8)?;

    // Compute commitment (stateless function)
    let secret = H256::random();
    let amount = U256::from(1000000u64);
    let blinding = H256::random();

    let commitment = compute_commitment(secret, amount, blinding)?;

    // Compute nullifier (stateless function)
    let leaf_index = 0u32;
    let nullifier = compute_nullifier(secret, leaf_index)?;

    // Build witness from pallet storage
    let merkle_path = Self::get_merkle_path(leaf_index)?;
    let witness = TransferWitness {
        secret,
        amount,
        blinding,
        leaf_index,
        merkle_path,
    };

    // Generate proof (uses cached keys from handle)
    let proof = privacy_system.prove_transfer(witness)?;

    // Submit back to blockchain
    Self::submit_proof(request_id, proof, commitment, nullifier)?;

    Ok(())
}
```

---

## Benefits of Rust-to-Rust FFI

| Aspect | Go FFI (Old) | Rust-to-Rust (New) |
|--------|--------------|-------------------|
| **ABI** | extern "C" | Native Rust |
| **Types** | C primitives | Rust types (H256, U256) |
| **Memory** | Manual (Box::into_raw) | Automatic (ownership) |
| **Safety** | Unsafe blocks | Safe (mostly) |
| **Errors** | Error codes (i32) | Result<T, E> |
| **Strings** | CString conversions | &str, String |
| **State** | Global Arc<RwLock<>> | None (pallet handles) |
| **Complexity** | High | Low |

---

## Migration Steps

### Step 1: Create New API Module

Create `privacy-lib/src/api.rs`:

```rust
//! Public stateless API for privacy operations

use ethereum_types::{Address, H256, U256};
use secp256k1::{PublicKey, SecretKey};
use std::sync::Arc;

pub use crate::error::PrivacyError;
pub use crate::circuits::halo_circuits::ProductionProofSystem;

/// Minimal privacy system handle
pub struct PrivacySystem {
    proof_system: Arc<ProductionProofSystem>,
}

impl PrivacySystem {
    pub fn new(k: u32, lookup_bits: u8) -> Result<Self, PrivacyError> {
        let proof_system = ProductionProofSystem::new(k, lookup_bits)
            .map_err(|e| PrivacyError::ProofSystemInit(e.to_string()))?;
        Ok(Self {
            proof_system: Arc::new(proof_system),
        })
    }

    // Proof methods here...
}

// Pure functions
pub fn poseidon_hash(left: H256, right: H256) -> H256 { ... }
pub fn compute_commitment(...) -> Result<H256, PrivacyError> { ... }
pub fn compute_nullifier(...) -> Result<H256, PrivacyError> { ... }
```

### Step 2: Update lib.rs

```rust
// privacy-lib/src/lib.rs

pub mod api;
pub mod crypto;
pub mod circuits;
pub mod stealth;
pub mod merkle;
pub mod nullifiers;
pub mod types;
pub mod error;

// Re-export public API
pub use api::*;
pub use types::*;
pub use error::*;

// Remove FFI modules
// pub mod ffi; // ❌ REMOVE
```

### Step 3: Update Cargo.toml

```toml
[lib]
name = "qoranet_privacy"
# Use rlib for Rust-to-Rust (no cdylib needed!)
crate-type = ["rlib"]

[dependencies]
# Make tokio non-optional (needed by proof system)
tokio = { version = "1.47.1", features = ["full"] }

# Remove: optional for tokio/futures
# tokio = { version = "1.47.1", features = ["full"], optional = true }
```

### Step 4: Test Build

```bash
cd privacy-lib
cargo +nightly-2024-09-01 build --release
```

---

## Next Implementation Steps

1. ✅ Create `api.rs` with stateless functions
2. ✅ Update `lib.rs` to export new API
3. ✅ Remove FFI modules (or comment out)
4. ✅ Fix Cargo.toml
5. ✅ Build and test privacy-lib
6. ✅ Create usage example in Frontier pallet
7. ✅ Test end-to-end

---

**Result**: Clean, safe, simple Rust-to-Rust interface with NO FFI overhead!
