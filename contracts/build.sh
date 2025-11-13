#!/bin/bash
# Compile QRC-20 Solidity contracts to bytecode for Rust embedding

set -e

CONTRACTS_DIR="$(dirname "$0")"
cd "$CONTRACTS_DIR"

echo "Compiling QRC-20 Solidity contracts..."

# Compile TokenFactory
echo "→ Compiling TokenFactory.sol..."
solc --optimize --optimize-runs 200 --via-ir --bin --abi TokenFactory.sol -o . --overwrite

# Compile QRC20Public
echo "→ Compiling QRC20Public.sol..."
solc --optimize --optimize-runs 200 --via-ir --bin --abi QRC20Public.sol -o . --overwrite

# Compile QRC20Private (QRC20P)
echo "→ Compiling QRC20Private.sol..."
solc --optimize --optimize-runs 200 --via-ir --bin --abi QRC20Private.sol -o . --overwrite

# Compile UniversalSwitch
echo "→ Compiling UniversalSwitch.sol..."
solc --optimize --optimize-runs 200 --via-ir --bin --abi UniversalSwitch.sol -o . --overwrite

echo ""
echo "✅ Contracts compiled successfully!"
echo ""
echo "Generated files:"
echo "  - TokenFactory.bin + TokenFactory.abi"
echo "  - QRC20Public.bin + QRC20Public.abi"
echo "  - QRC20Private.bin + QRC20Private.abi (QRC20P)"
echo "  - UniversalSwitch.bin + UniversalSwitch.abi"
echo ""
echo "These bytecode files are embedded in the runtime using include_bytes!()"
