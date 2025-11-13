# Smart Contracts - Privacy & Token System

This directory contains production Solidity contracts from Qora for privacy-enabled tokens.

## 📁 Directory: `contracts/`

### Smart Contracts (980 lines total)

| Contract | Lines | Purpose | Status |
|----------|-------|---------|--------|
| `QRC20Private.sol` | 308 | Privacy-enabled ERC-20 token | ✅ Ready |
| `QRC20Public.sol` | 398 | Public ERC-20 token | ✅ Ready |
| `UniversalSwitch.sol` | 170 | Public ↔ Private token switching | ✅ Ready |
| `QRC20Registry.sol` | 55 | Token registry | ✅ Ready |
| `QoraNetGovernance.sol` | 49 | Governance system | ✅ Ready |

### Compiled Artifacts

**ABIs** (Application Binary Interface):
- `QRC20P.abi` - Privacy token ABI (6.6KB)
- `QRC20Public.abi` - Public token ABI (8.1KB)
- `QRC20Registry.abi` - Registry ABI (2.4KB)
- `UniversalSwitch.abi` - Switch ABI (4.7KB)

**Bytecode**:
- `QRC20P.bin` - Privacy token bytecode (17KB)
- `QRC20Public.bin` - Public token bytecode (22KB)
- `QRC20Registry.bin` - Registry bytecode (5.5KB)
- `UniversalSwitch.bin` - Switch bytecode (9.4KB)

### Tools

- `solc.exe` (9.0MB) - Solidity compiler v0.8.x
- `build.sh` - Build script for contracts

## 📁 Directory: `params/`

### Halo2 Circuit Parameters

| File | Size | Purpose | Circuit Size |
|------|------|---------|--------------|
| `halo2_k17.params` | 17MB | Halo2 proving/verifying keys | 2^17 constraints |

**What is this?**
- Contains setup parameters for Halo2 ZK-SNARK circuits
- **k=17** means circuit supports up to **131,072 constraints** (2^17)
- Generated via Powers of Tau ceremony (no trusted setup!)
- Required for proof generation and verification

**Usage**:
```rust
// Load parameters
let params = load_params("privacy-lib/params/halo2_k17.params")?;

// Generate proof
let proof = generate_proof(&circuit, &params)?;

// Verify proof
verify_proof(&proof, &public_inputs, &params)?;
```

## 🔗 Integration with QoraNet Blockcian L1

### How These Contracts Work with Privacy Layer

1. **Privacy Deposits**:
   ```solidity
   QRC20Public.transfer(100) → UniversalSwitch.switchToPrivate(100)
   → Generates commitment via Rust privacy-lib
   → Adds to Merkle tree
   → Emits event for off-chain tracking
   ```

2. **Privacy Withdrawals**:
   ```solidity
   UniversalSwitch.switchToPublic(commitment, nullifier, proof)
   → Verifies ZK proof via precompile
   → Checks nullifier not used
   → Transfers QRC20Public tokens to user
   ```

3. **Registry**:
   ```solidity
   QRC20Registry.registerToken(tokenAddress)
   → Tracks all privacy-enabled tokens
   → Maps token ID to contract address
   ```

### Deployment on QoraNet Blockcian L1

**Step 1: Deploy Registry**
```bash
# Deploy QRC20Registry
forge create QRC20Registry --rpc-url http://localhost:9944
```

**Step 2: Deploy Token Contracts**
```bash
# Deploy public token
forge create QRC20Public --constructor-args "MyToken" "MTK" 1000000

# Deploy UniversalSwitch (links to privacy precompile 0x800)
forge create UniversalSwitch --constructor-args $PUBLIC_TOKEN_ADDR
```

**Step 3: Register Token**
```bash
# Register in registry
cast send $REGISTRY_ADDR "registerToken(address)" $PUBLIC_TOKEN_ADDR
```

## 🔧 Contract Features

### QRC20Private.sol

**Key Functions**:
```solidity
function deposit(uint256 amount, bytes32 commitment) external
function withdraw(bytes32 nullifier, bytes calldata proof) external
function getCommitmentRoot() external view returns (bytes32)
```

**Privacy Features**:
- ZK-SNARK proof verification
- Merkle tree commitment storage
- Nullifier tracking (prevent double-spend)
- Stealth address support

### QRC20Public.sol

**Standard ERC-20**:
```solidity
function transfer(address to, uint256 amount) external
function approve(address spender, uint256 amount) external
function transferFrom(address from, address to, uint256 amount) external
```

### UniversalSwitch.sol

**Switching Functions**:
```solidity
function switchToPrivate(uint256 amount, bytes32 commitment) external
function switchToPublic(bytes32 nullifier, bytes calldata proof, uint256 amount) external
```

**How It Works**:
1. User locks public tokens in contract
2. Contract calls privacy precompile (0x800) to create commitment
3. User can spend privately off-chain
4. When withdrawing, provide ZK proof
5. Contract verifies proof via precompile
6. Unlocks public tokens to user

## 🧪 Testing

### Test Privacy Flow

```bash
cd privacy-lib/contracts

# 1. Deploy contracts
./build.sh

# 2. Mint some tokens
cast send $PUBLIC_TOKEN "mint(address,uint256)" $USER 1000000

# 3. Switch to private
cast send $UNIVERSAL_SWITCH "switchToPrivate(uint256,bytes32)" 100 $COMMITMENT

# 4. Generate ZK proof (Rust side)
cargo run --bin generate_proof -- --amount 100 --nullifier $NULLIFIER

# 5. Switch back to public
cast send $UNIVERSAL_SWITCH "switchToPublic(bytes32,bytes,uint256)" \
  $NULLIFIER $PROOF 100
```

## 🔐 Security Considerations

### Smart Contract Security

✅ **Already Audited in Qora**:
- Reentrancy protection (using OpenZeppelin patterns)
- Integer overflow/underflow checks (Solidity 0.8+)
- Access control (only authorized addresses)
- Nullifier tracking (prevent double-spend)

⚠️ **Additional Checks for QoraNet Blockcian L1**:
- Verify precompile addresses match (0x800 for privacy)
- Test gas costs on Blockcian (might differ from Qora)
- Ensure Merkle root synchronization
- Rate limiting for privacy operations

### Privacy Guarantees

**What's Private**:
- ✅ Transaction amounts (hidden in commitments)
- ✅ Sender identity (stealth addresses)
- ✅ Recipient identity (stealth addresses)
- ✅ Transaction graph (via Dandelion++)

**What's Public**:
- ⚠️ Public → Private switches (amount visible on switch)
- ⚠️ Private → Public switches (amount visible on switch)
- ⚠️ Timing analysis (if not using Dandelion++)

**Best Practices**:
- Use amount splitting to hide exact amounts
- Wait random time before withdrawals
- Use Dandelion++ for transaction broadcasting
- Switch in/out at common denominations

## 📚 Reference

### Contract Addresses (After Deployment)

```yaml
# Save these after deploying to testnet
registry: "0x..."
public_token: "0x..."
universal_switch: "0x..."
governance: "0x..."
```

### Precompile Addresses (QoraNet Blockcian L1)

```rust
// In runtime/src/precompiles.rs
pub const PRIVACY_PRECOMPILE: H160 = H160([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x08,0x00]); // 0x800
```

### Gas Costs

| Operation | Estimated Gas | Notes |
|-----------|--------------|-------|
| Deposit (Public → Private) | 150,000 | Includes Merkle update |
| Withdraw (Private → Public) | 250,000 | Includes ZK proof verification |
| Transfer (Public) | 21,000 | Standard ERC-20 |
| Proof verification | 180,000 | Halo2 verification in precompile |

## 🛠️ Development

### Modify Contracts

1. Edit `.sol` files in `contracts/`
2. Rebuild:
   ```bash
   ./build.sh
   ```
3. Test:
   ```bash
   forge test
   ```
4. Deploy to testnet:
   ```bash
   forge create --rpc-url http://localhost:9944
   ```

### Add New Privacy Features

1. Update Rust privacy-lib (add new circuit)
2. Update precompile to expose new function
3. Update UniversalSwitch.sol to call precompile
4. Test end-to-end

---

**Maintained By**: QoraNet Blockcian Team
**Last Updated**: 2025-01-22
**Contract Version**: v2.0 (from Qora)
