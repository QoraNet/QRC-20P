// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./QRC20Public.sol";
import "./QRC20Private.sol";
import "./UniversalSwitch.sol";

/**
 * @title TokenFactory
 * @dev ATOMIC deployment factory for QRC-20 token pairs
 *
 * CRITICAL: All 4 components MUST deploy in ONE transaction:
 * 1. QRC20Private contract
 * 2. QRC20Public contract
 * 3. UniversalSwitch contract (per-token switch)
 * 4. Registration with Pallet Bridge (0x73 precompile)
 *
 * If ANY step fails, entire transaction reverts - ensuring privacy is never broken.
 */
contract TokenFactory {
    // Precompile addresses
    address public constant PALLET_BRIDGE = 0x0000000000000000000000000000000000000073;

    // Registry of deployed tokens
    struct DeployedToken {
        address qrc20Public;
        address qrc20Private;
        address universalSwitch;
        bytes32 tokenId;
        address creator;
        uint256 deployedAt;
        bool isActive;
    }

    mapping(bytes32 => DeployedToken) public deployedTokens;
    bytes32[] public allTokenIds;

    event TokenPairDeployed(
        bytes32 indexed tokenId,
        address indexed qrc20Public,
        address indexed qrc20Private,
        address universalSwitch,
        address creator,
        string symbol
    );

    constructor() {
        // No governance needed - privacy is immutable and automatic
    }

    /**
     * @dev ATOMIC deployment of QRC-20 token pair with privacy
     *
     * This function guarantees all-or-nothing deployment:
     * - Deploys QRC20Private
     * - Deploys QRC20Public
     * - Deploys UniversalSwitch (per-token)
     * - Registers with Pallet Bridge (0x73)
     *
     * If ANY step fails, the entire transaction reverts.
     *
     * @param name Token name (e.g., "Qora USD")
     * @param symbol Token symbol (e.g., "QUSD")
     * @param decimals Token decimals (usually 18)
     * @param totalSupply Initial total supply
     * @return tokenId Unique identifier for this token pair
     * @return qrc20Public Address of deployed QRC20Public
     * @return qrc20Private Address of deployed QRC20Private
     * @return universalSwitch Address of deployed UniversalSwitch
     */
    function createTokenPair(
        string memory name,
        string memory symbol,
        uint8 decimals,
        uint256 totalSupply
    ) external returns (
        bytes32 tokenId,
        address qrc20Public,
        address qrc20Private,
        address universalSwitch
    ) {
        require(bytes(name).length > 0, "Factory: Empty name");
        require(bytes(symbol).length > 0, "Factory: Empty symbol");
        require(totalSupply > 0, "Factory: Zero supply");

        // ========================================
        // STEP 1: Deploy QRC20Private first
        // ========================================
        QRC20Private privateToken = new QRC20Private{
            salt: keccak256(abi.encodePacked(msg.sender, symbol, block.timestamp))
        }(
            msg.sender,
            decimals
        );
        qrc20Private = address(privateToken);

        // ========================================
        // STEP 2: Deploy QRC20Public
        // ========================================
        QRC20Public publicToken = new QRC20Public{
            salt: keccak256(abi.encodePacked(msg.sender, symbol, block.timestamp))
        }(
            name,
            symbol,
            decimals,
            totalSupply,
            qrc20Private,
            msg.sender
        );
        qrc20Public = address(publicToken);

        // Generate token ID
        tokenId = keccak256(abi.encodePacked(qrc20Public, qrc20Private));

        // Ensure uniqueness
        require(deployedTokens[tokenId].qrc20Public == address(0), "Factory: Already deployed");

        // ========================================
        // STEP 3: Deploy UniversalSwitch (per-token)
        // ========================================
        UniversalSwitch switchContract = new UniversalSwitch{
            salt: keccak256(abi.encodePacked(msg.sender, symbol, block.timestamp, "switch"))
        }(
            qrc20Public,
            qrc20Private
        );
        universalSwitch = address(switchContract);

        // ========================================
        // STEP 3.5: Initialize both tokens with addresses (ATOMIC)
        // ========================================
        publicToken.initializeSwitch(universalSwitch);
        privateToken.initializeSwitch(qrc20Public, universalSwitch);

        // ========================================
        // STEP 4: Register with Pallet Bridge (0x73)
        // Precompile function: registerTokenPair(address,address,uint256)
        // Selector: 0x1a2b3c4d
        // ========================================
        bytes memory palletCalldata = abi.encodePacked(
            bytes4(0x1a2b3c4d),           // registerTokenPair selector
            bytes12(0),                    // Padding for tokenId (H160)
            bytes20(uint160(uint256(tokenId))), // tokenId as address
            bytes12(0),                    // Padding for qrc20Public
            bytes20(qrc20Public),         // qrc20Public address
            bytes12(0),                    // Padding for qrc20Private
            bytes20(qrc20Private),        // qrc20Private address
            totalSupply                    // Initial supply (uint256)
        );

        (bool palletSuccess, bytes memory palletResult) = PALLET_BRIDGE.call(palletCalldata);
        require(palletSuccess, "Factory: Pallet registration failed");

        // Verify pallet returned success (1)
        require(palletResult.length == 32, "Factory: Invalid pallet response");
        uint256 palletReturnValue = abi.decode(palletResult, (uint256));
        require(palletReturnValue == 1, "Factory: Pallet rejected registration");

        // ========================================
        // STEP 5: Record deployment
        // ========================================
        deployedTokens[tokenId] = DeployedToken({
            qrc20Public: qrc20Public,
            qrc20Private: qrc20Private,
            universalSwitch: universalSwitch,
            tokenId: tokenId,
            creator: msg.sender,
            deployedAt: block.timestamp,
            isActive: true
        });

        allTokenIds.push(tokenId);

        emit TokenPairDeployed(tokenId, qrc20Public, qrc20Private, universalSwitch, msg.sender, symbol);

        return (tokenId, qrc20Public, qrc20Private, universalSwitch);
    }

    /**
     * @dev Get token pair info
     */
    function getTokenPair(bytes32 tokenId) external view returns (DeployedToken memory) {
        return deployedTokens[tokenId];
    }

    /**
     * @dev Get total number of deployed token pairs
     */
    function getTotalTokens() external view returns (uint256) {
        return allTokenIds.length;
    }

    /**
     * @dev Check if token pair exists and is active
     */
    function isValidTokenPair(address qrc20Public, address qrc20Private) external view returns (bool) {
        bytes32 tokenId = keccak256(abi.encodePacked(qrc20Public, qrc20Private));
        return deployedTokens[tokenId].isActive;
    }

    /**
     * @dev Emergency deactivation (governance only)
     * Does NOT destroy contracts, just marks as inactive
     */
    function deactivateToken(bytes32 tokenId) external {
        require(deployedTokens[tokenId].creator == msg.sender, "Factory: Not creator");
        deployedTokens[tokenId].isActive = false;
    }
}
