# FFI Import Fixes - Get it Building

## Changes Needed in Each FFI File

### 1. Cargo.toml - Make tokio non-optional

```toml
# BEFORE:
tokio = { version = "1.47.1", features = ["full"], optional = true }
futures = { version = "0.3", optional = true }

# AFTER:
tokio = { version = "1.47.1", features = ["full"] }
futures = { version = "0.3" }
```

### 2. ffi.rs - Fix imports and remove missing modules

**Lines 9-24 - BEFORE:**
```rust
use tokio::sync::RwLock;
use once_cell::sync::Lazy;

use ethereum_types::{Address, H256, U256};
use hex;

use super::secure_privacy::{SecurePrivacyPool, PrivacyConfig};
use super::common_types::{TokenId, TokenMode};
use super::state::GlobalState;
use super::privacy::PrivacyStateManager;
use super::fees_usd::{USDFeeSystem, FeeConfig};
use super::universal_switch::{UniversalSwitch, SwitchConfig};
use super::token_factory::TokenFactory;
use super::stealth_addresses::StealthAddressManager;
use super::network_privacy::{NetworkPrivacyLayer, NetworkPrivacyConfig, NetworkInterface};
use super::halo2_circuits::ProductionProofSystem;
```

**AFTER:**
```rust
use tokio::sync::RwLock;
use once_cell::sync::Lazy;

use ethereum_types::{Address, H256, U256};
use hex;

use crate::nullifiers::secure_privacy::{SecurePrivacyPool, PrivacyConfig};  // ✅ Fixed path
use crate::common_types::{TokenId, TokenMode};  // ✅ Fixed path
// Removed: use super::state::GlobalState;  // ❌ Doesn't exist
// Removed: use super::privacy::PrivacyStateManager;  // ❌ Doesn't exist (secure_privacy IS the privacy module)
// Removed: use super::fees_usd::{USDFeeSystem, FeeConfig};  // ❌ Doesn't exist, blockchain handles fees
use crate::universal_switch::{UniversalSwitch, SwitchConfig};  // ✅ Fixed path
use crate::token_factory::TokenFactory;  // ✅ Fixed path
use crate::stealth::stealth_addresses::StealthAddressManager;  // ✅ Fixed path
#[cfg(feature = "network")]
use crate::network_privacy::{NetworkPrivacyLayer, NetworkPrivacyConfig, NetworkInterface};  // ✅ Fixed path + feature gate
use crate::circuits::halo_circuits::ProductionProofSystem;  // ✅ Fixed name (halo2_circuits → halo_circuits)
```

**Lines 67-75 - BEFORE (PrivacySystemHandle):**
```rust
pub struct PrivacySystemHandle {
    pub(crate) privacy_pool: SecurePrivacyPool,
    pub(crate) global_state: Arc<RwLock<GlobalState>>,
    pub(crate) universal_switch: Arc<UniversalSwitch>,
    pub(crate) token_factory: Arc<TokenFactory>,
    pub(crate) stealth_manager: Arc<StealthAddressManager>,
    pub(crate) network_privacy: Arc<crate::privacy::network_privacy::NetworkPrivacyLayer>,
    pub(crate) atomic_state: Arc<crate::privacy::atomic_state::AtomicPrivacyState>,
}
```

**AFTER:**
```rust
pub struct PrivacySystemHandle {
    pub(crate) privacy_pool: SecurePrivacyPool,
    // Removed: pub(crate) global_state: Arc<RwLock<GlobalState>>,  // ❌ Doesn't exist
    pub(crate) universal_switch: Arc<UniversalSwitch>,
    pub(crate) token_factory: Arc<TokenFactory>,
    pub(crate) stealth_manager: Arc<StealthAddressManager>,
    #[cfg(feature = "network")]
    pub(crate) network_privacy: Arc<NetworkPrivacyLayer>,  // ✅ Fixed path + feature gate
    // Removed: pub(crate) atomic_state: Arc<crate::privacy::atomic_state::AtomicPrivacyState>,  // ❌ Doesn't exist
}
```

**Lines 116-186 - BEFORE (privacy_init):**
```rust
pub extern "C" fn privacy_init() -> *mut c_void {
    let _guard = FFI_RUNTIME.enter();

    let config = PrivacyConfig::default();
    let global_state = Arc::new(tokio::sync::RwLock::new(GlobalState::new()));
    let fee_system = Arc::new(tokio::sync::RwLock::new(USDFeeSystem::new(FeeConfig::default())));

    let proof_system = match ProductionProofSystem::new(17, 8) {
        Ok(ps) => Arc::new(ps),
        Err(e) => {
            tracing::error!("Failed to initialize proof system: {}", e);
            return ptr::null_mut();
        }
    };

    let privacy_pool = SecurePrivacyPool::new(
        config,
        H256::zero(),
        proof_system.clone(),
    );

    let universal_switch = UniversalSwitch::new(SwitchConfig::default(), proof_system.clone());
    let privacy_manager = Arc::new(RwLock::new(PrivacyStateManager::new()));
    let token_factory = Arc::new(TokenFactory::new(
        universal_switch.clone(),
        privacy_manager,
        global_state.clone(),
        fee_system.clone(),
    ));

    let stealth_manager = Arc::new(StealthAddressManager::new());
    let network_config = NetworkPrivacyConfig::default();
    let network_interface = Arc::new(NetworkInterface::new());
    let network_privacy = Arc::new(NetworkPrivacyLayer::new(network_config, network_interface));
    network_privacy.start_cleanup_task();
    let atomic_state = Arc::new(crate::privacy::atomic_state::AtomicPrivacyState::new());

    let handle = PrivacySystemHandle {
        privacy_pool,
        global_state,
        universal_switch,
        token_factory,
        stealth_manager,
        network_privacy,
        atomic_state,
    };
    // ... rest
}
```

**AFTER:**
```rust
#[no_mangle]
pub extern "C" fn privacy_init() -> *mut c_void {
    let _guard = FFI_RUNTIME.enter();

    let config = PrivacyConfig::default();
    // Removed: let global_state = Arc::new(tokio::sync::RwLock::new(GlobalState::new()));
    // Removed: let fee_system = Arc::new(tokio::sync::RwLock::new(USDFeeSystem::new(FeeConfig::default())));

    let proof_system = match ProductionProofSystem::new(17, 8) {
        Ok(ps) => Arc::new(ps),
        Err(e) => {
            tracing::error!("Failed to initialize proof system: {}", e);
            return ptr::null_mut();
        }
    };

    let privacy_pool = SecurePrivacyPool::new(
        config,
        H256::zero(),
        proof_system.clone(),
    );

    let universal_switch = UniversalSwitch::new(SwitchConfig::default(), proof_system.clone());
    // Removed: let privacy_manager = Arc::new(RwLock::new(PrivacyStateManager::new()));

    // TODO: token_factory constructor needs to be updated - it expects these removed params
    // For now, comment out or we need to check what TokenFactory::new actually expects
    // let token_factory = Arc::new(TokenFactory::new(...));

    let stealth_manager = Arc::new(StealthAddressManager::new());

    #[cfg(feature = "network")]
    let network_privacy = {
        let network_config = NetworkPrivacyConfig::default();
        let network_interface = Arc::new(NetworkInterface::new());
        let np = Arc::new(NetworkPrivacyLayer::new(network_config, network_interface));
        np.start_cleanup_task();
        np
    };

    // Removed: let atomic_state = Arc::new(crate::privacy::atomic_state::AtomicPrivacyState::new());

    let handle = PrivacySystemHandle {
        privacy_pool,
        // Removed: global_state,
        universal_switch,
        // token_factory,  // TODO: needs constructor fix
        stealth_manager,
        #[cfg(feature = "network")]
        network_privacy,
        // Removed: atomic_state,
    };

    let wrapper = Box::new(PrivacySystemHandleWrapper {
        magic: PRIVACY_HANDLE_MAGIC,
        handle,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs(),
    });

    Box::into_raw(wrapper) as *mut c_void
}
```

### 3. ffi_precompiles.rs - Fix imports

**Lines 9-10 - BEFORE:**
```rust
use crate::privacy::poseidon::poseidon_hash as poseidon_hash_fn;
use crate::privacy::halo2_circuits::ProductionProofSystem;
```

**AFTER:**
```rust
use crate::crypto::poseidon::poseidon_hash as poseidon_hash_fn;  // ✅ Fixed path
use crate::circuits::halo_circuits::ProductionProofSystem;  // ✅ Fixed path
```

### 4. ffi_private_transfer.rs - Fix imports

**Lines 7-14 - BEFORE:**
```rust
use crate::privacy::{
    ffi::{FFI_RUNTIME, PrivacySystemHandleWrapper, validate_handle_wrapper_mut},
    ...
};
```

**AFTER:**
```rust
use crate::ffi::{FFI_RUNTIME, PrivacySystemHandleWrapper, validate_handle_wrapper_mut};
use crate::nullifiers::secure_privacy::{SecureNullifierGenerator, SecureCommitmentScheme};
// Other imports as needed
```

### 5. ffi_dual_token.rs - Fix imports

**Lines 6-7 - BEFORE:**
```rust
use crate::privacy::common_types::TokenId;
use crate::privacy::ffi::{FFI_RUNTIME, PrivacySystemHandleWrapper, validate_handle_wrapper_mut};
```

**AFTER:**
```rust
use crate::common_types::TokenId;
use crate::ffi::{FFI_RUNTIME, PrivacySystemHandleWrapper, validate_handle_wrapper_mut};
```

### 6. ffi_universal_switch.rs - Fix imports

**Lines 11-13 - BEFORE:**
```rust
use super::universal_switch::{UniversalSwitch, SwitchConfig};
// ...
use super::halo2_circuits::ProductionProofSystem;
```

**AFTER:**
```rust
use crate::universal_switch::{UniversalSwitch, SwitchConfig};
// ...
use crate::circuits::halo_circuits::ProductionProofSystem;
```

### 7. ffi_amount_privacy.rs - Fix imports

**Line 8 - BEFORE:**
```rust
use super::amount_splitter::{AmountSplitter, AmountMixer};
```

**AFTER:**
```rust
#[cfg(feature = "network")]
use crate::amount_splitter::{AmountSplitter, AmountMixer};
```

## Additional Issues to Address

### TokenFactory Constructor

Need to check what `TokenFactory::new()` actually expects. If it requires the removed params (global_state, fee_system), we have two options:

1. **Comment it out for now** - Get a minimal build first
2. **Update TokenFactory** - Remove state/fee params from its constructor

### Atomic State References

Several files reference `crate::privacy::atomic_state::AtomicPrivacyState` which doesn't exist. These need to be:
- Commented out OR
- Replaced with blockchain transaction handling

### Network Privacy Feature

Make sure to build with `--features std` (not `--features std,network`) to avoid network privacy dependencies initially.

## Build Command

```bash
cd D:\Downloads\QoraNet+Blockcian-V1\privacy-lib

# First, try building without FFI modules to verify base library works
cargo +nightly-2024-09-01 build --release --features std --lib

# Then try with FFI (after fixes)
cargo +nightly-2024-09-01 build --release --features std
```

## Expected Result

After these fixes:
- ✅ Compilation should complete (may have warnings)
- ✅ DLL should be created: `target/release/qoranet_privacy.dll`
- ⚠️ Some FFI functions may not work fully (due to removed state)
- ⚠️ Will need further refactoring for stateless blockchain integration

## Next Steps After Building

1. Verify DLL exports: `dumpbin /EXPORTS qoranet_privacy.dll`
2. Create minimal C test program
3. Identify which FFI functions actually work
4. Plan Phase 2: Redesign for stateless architecture
