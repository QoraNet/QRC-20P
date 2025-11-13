// QoraNet Blockcian - Complete Privacy System Deployment Script
//
// This script deploys the FULL privacy infrastructure:
// 1. UniversalSwitch (0x20) - Singleton coordinator
// 2. TokenFactory - Atomic deployment manager
// 3. First token pair (QUSD) - Qora USD stablecoin
//
// Requirements:
// - Node running with EVM enabled
// - ethers.js or web3.js
// - Deployer account with funds

const { ethers } = require("hardhat");

// Precompile addresses (must match runtime configuration)
const PRECOMPILE_ADDRESSES = {
    UNIVERSAL_SWITCH: "0x0000000000000000000000000000000000000020",
    PALLET_BRIDGE: "0x0000000000000000000000000000000000000073",
    POSEIDON: "0x0000000000000000000000000000000000000071",
    ZK_VERIFIER: "0x0000000000000000000000000000000000000072",
};

async function main() {
    console.log("╔════════════════════════════════════════════════════════════╗");
    console.log("║   QoraNet Blockcian - Privacy System Deployment           ║");
    console.log("║   FULL PRIVACY - NO COMPROMISES                            ║");
    console.log("╚════════════════════════════════════════════════════════════╝");
    console.log("");

    const [deployer] = await ethers.getSigners();
    console.log("Deployer address:", deployer.address);
    console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH");
    console.log("");

    // ========================================
    // STEP 1: Deploy UniversalSwitch to 0x20
    // ========================================
    console.log("┌─────────────────────────────────────────────────────────┐");
    console.log("│ STEP 1: Deploy UniversalSwitch (Singleton)             │");
    console.log("└─────────────────────────────────────────────────────────┘");

    // Check if UniversalSwitch already exists at 0x20
    const existingCode = await ethers.provider.getCode(PRECOMPILE_ADDRESSES.UNIVERSAL_SWITCH);
    let universalSwitch;

    if (existingCode === "0x" || existingCode === "0x0") {
        console.log("❌ UniversalSwitch NOT found at 0x20");
        console.log("   Deploying new UniversalSwitch...");

        const UniversalSwitch = await ethers.getContractFactory("UniversalSwitch");
        universalSwitch = await UniversalSwitch.deploy(
            deployer.address, // treasury
            deployer.address  // governance
        );
        await universalSwitch.waitForDeployment();

        const deployedAddr = await universalSwitch.getAddress();
        console.log("✅ UniversalSwitch deployed at:", deployedAddr);

        if (deployedAddr.toLowerCase() !== PRECOMPILE_ADDRESSES.UNIVERSAL_SWITCH.toLowerCase()) {
            console.warn("⚠️  WARNING: Deployed at different address than expected!");
            console.warn("   Expected:", PRECOMPILE_ADDRESSES.UNIVERSAL_SWITCH);
            console.warn("   Got:     ", deployedAddr);
            console.warn("   You may need to use a specific nonce/CREATE2 to deploy to 0x20");
        }
    } else {
        console.log("✅ UniversalSwitch already deployed at 0x20");
        universalSwitch = await ethers.getContractAt("UniversalSwitch", PRECOMPILE_ADDRESSES.UNIVERSAL_SWITCH);
    }
    console.log("");

    // ========================================
    // STEP 2: Verify Precompiles
    // ========================================
    console.log("┌─────────────────────────────────────────────────────────┐");
    console.log("│ STEP 2: Verify Precompiles                             │");
    console.log("└─────────────────────────────────────────────────────────┘");

    const precompiles = [
        { name: "Poseidon Hash", addr: PRECOMPILE_ADDRESSES.POSEIDON },
        { name: "ZK Verifier", addr: PRECOMPILE_ADDRESSES.ZK_VERIFIER },
        { name: "Pallet Bridge", addr: PRECOMPILE_ADDRESSES.PALLET_BRIDGE },
    ];

    for (const p of precompiles) {
        const code = await ethers.provider.getCode(p.addr);
        if (code !== "0x" && code !== "0x0") {
            console.log(`✅ ${p.name.padEnd(20)} ${p.addr}`);
        } else {
            console.log(`❌ ${p.name.padEnd(20)} ${p.addr} - NOT FOUND`);
            console.log("   ERROR: Precompile missing! Check runtime configuration.");
            process.exit(1);
        }
    }
    console.log("");

    // ========================================
    // STEP 3: Deploy TokenFactory
    // ========================================
    console.log("┌─────────────────────────────────────────────────────────┐");
    console.log("│ STEP 3: Deploy TokenFactory                            │");
    console.log("└─────────────────────────────────────────────────────────┘");

    const TokenFactory = await ethers.getContractFactory("TokenFactory");
    const tokenFactory = await TokenFactory.deploy();
    await tokenFactory.waitForDeployment();

    const factoryAddr = await tokenFactory.getAddress();
    console.log("✅ TokenFactory deployed at:", factoryAddr);
    console.log("");

    // ========================================
    // STEP 4: Deploy First Token Pair (QUSD)
    // ========================================
    console.log("┌─────────────────────────────────────────────────────────┐");
    console.log("│ STEP 4: Deploy First Token Pair (QUSD - Qora USD)      │");
    console.log("└─────────────────────────────────────────────────────────┘");

    const tokenConfig = {
        name: "Qora USD",
        symbol: "QUSD",
        decimals: 18,
        totalSupply: ethers.parseEther("1000000"), // 1M QUSD
        switchFee: ethers.parseEther("0.001"), // 0.001 ETH per switch
    };

    console.log("Token configuration:");
    console.log("  Name:         ", tokenConfig.name);
    console.log("  Symbol:       ", tokenConfig.symbol);
    console.log("  Decimals:     ", tokenConfig.decimals);
    console.log("  Total Supply: ", ethers.formatEther(tokenConfig.totalSupply), tokenConfig.symbol);
    console.log("  Switch Fee:   ", ethers.formatEther(tokenConfig.switchFee), "ETH");
    console.log("");

    console.log("🚀 Creating token pair (ATOMIC transaction)...");
    console.log("   This will:");
    console.log("   1. Deploy QRC20Private");
    console.log("   2. Deploy QRC20Public");
    console.log("   3. Register with UniversalSwitch (0x20)");
    console.log("   4. Register with Pallet Bridge (0x73)");
    console.log("   5. Record in TokenFactory");
    console.log("   ALL-OR-NOTHING guarantee!");
    console.log("");

    const tx = await tokenFactory.createTokenPair(
        tokenConfig.name,
        tokenConfig.symbol,
        tokenConfig.decimals,
        tokenConfig.totalSupply,
        tokenConfig.switchFee
    );

    console.log("⏳ Transaction submitted:", tx.hash);
    console.log("   Waiting for confirmation...");

    const receipt = await tx.wait();

    if (receipt.status === 1) {
        console.log("✅ Token pair created successfully!");
        console.log("");

        // Extract addresses from event
        const event = receipt.logs.find(log => {
            try {
                return tokenFactory.interface.parseLog(log)?.name === "TokenPairDeployed";
            } catch {
                return false;
            }
        });

        if (event) {
            const parsedEvent = tokenFactory.interface.parseLog(event);
            const { tokenId, qrc20Public, qrc20Private } = parsedEvent.args;

            console.log("📋 Deployment Summary:");
            console.log("  Token ID:      ", tokenId);
            console.log("  QRC20Public:   ", qrc20Public);
            console.log("  QRC20Private:  ", qrc20Private);
            console.log("  Creator:       ", deployer.address);
            console.log("");

            // Verify token pair registration
            const tokenPair = await tokenFactory.getTokenPair(tokenId);
            console.log("✅ Verified in TokenFactory:");
            console.log("   Active:        ", tokenPair.isActive);
            console.log("   Deployed At:   ", new Date(Number(tokenPair.deployedAt) * 1000).toISOString());
            console.log("");

            // Check balances
            const QRC20Public = await ethers.getContractAt("QRC20Public", qrc20Public);
            const deployerBalance = await QRC20Public.balanceOf(deployer.address);
            console.log("✅ Token balances:");
            console.log("   Deployer:      ", ethers.formatEther(deployerBalance), tokenConfig.symbol);
            console.log("");
        }
    } else {
        console.log("❌ Transaction FAILED!");
        console.log("   Privacy system NOT deployed - atomic guarantee worked!");
        process.exit(1);
    }

    // ========================================
    // STEP 5: Summary
    // ========================================
    console.log("╔════════════════════════════════════════════════════════════╗");
    console.log("║   DEPLOYMENT COMPLETE                                      ║");
    console.log("╚════════════════════════════════════════════════════════════╝");
    console.log("");
    console.log("🎉 QoraNet Blockcian privacy infrastructure deployed!");
    console.log("");
    console.log("Next steps:");
    console.log("1. Test privacy switch: npm run test:privacy");
    console.log("2. Deploy more tokens: Use TokenFactory.createTokenPair()");
    console.log("3. Integrate with frontend: Use deployed contract addresses");
    console.log("");
    console.log("Contract Addresses:");
    console.log("  UniversalSwitch:  ", PRECOMPILE_ADDRESSES.UNIVERSAL_SWITCH);
    console.log("  TokenFactory:     ", factoryAddr);
    console.log("  Pallet Bridge:    ", PRECOMPILE_ADDRESSES.PALLET_BRIDGE);
    console.log("  Poseidon:         ", PRECOMPILE_ADDRESSES.POSEIDON);
    console.log("  ZK Verifier:      ", PRECOMPILE_ADDRESSES.ZK_VERIFIER);
    console.log("");
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("❌ Deployment failed:");
        console.error(error);
        process.exit(1);
    });
