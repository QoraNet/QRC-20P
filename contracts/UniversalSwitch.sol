// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title UniversalSwitch
 * @dev Per-token privacy switch contract - each token has its own instance
 * Deployed separately for each token pair (not a shared precompile)
 */
contract UniversalSwitch {
    // This token's information (single token, not a registry)
    address public immutable qrc20;          // Public contract
    address public immutable qrc20p;         // Private contract
    bytes32 public immutable tokenId;

    event TokenPairInitialized(
        bytes32 indexed tokenId,
        address indexed qrc20,
        address indexed qrc20p
    );

    event ModeSwitch(
        bytes32 indexed tokenId,
        address indexed user,
        bool toPrivate,
        uint256 amount,
        bytes32 commitment
    );

    constructor(
        address _qrc20,
        address _qrc20p
    ) {
        require(_qrc20 != address(0), "Invalid QRC-20");
        require(_qrc20p != address(0), "Invalid QRC-20P");

        qrc20 = _qrc20;
        qrc20p = _qrc20p;
        tokenId = keccak256(abi.encodePacked(_qrc20, _qrc20p));

        emit TokenPairInitialized(tokenId, _qrc20, _qrc20p);
    }

    /**
     * @dev Process public → private switch
     * Called by QRC-20 contract
     */
    function processPublicToPrivate(
        address user,
        uint256 amount,
        bytes32 commitment
    ) external {
        require(msg.sender == qrc20, "Only QRC-20");

        // Call QRC-20P to add commitment
        (bool success, ) = qrc20p.call(
            abi.encodeWithSignature(
                "shieldFromPublic(bytes32,uint256)",
                commitment,
                amount
            )
        );
        require(success, "Shield failed");

        emit ModeSwitch(tokenId, user, true, amount, commitment);
    }

    /**
     * @dev Process private → public switch
     * Called by QRC-20P contract
     */
    function processPrivateToPublic(
        address recipient,
        uint256 amount,
        bytes32 nullifier
    ) external {
        require(msg.sender == qrc20p, "Only QRC-20P");

        // Call QRC-20 to mint
        (bool success, ) = qrc20.call(
            abi.encodeWithSignature(
                "mintFromPrivate(address,uint256)",
                recipient,
                amount
            )
        );
        require(success, "Mint failed");

        emit ModeSwitch(tokenId, recipient, false, amount, nullifier);
    }

    /**
     * @dev Get token pair info
     */
    function getTokenInfo() external view returns (
        address _qrc20,
        address _qrc20p,
        bytes32 _tokenId
    ) {
        return (qrc20, qrc20p, tokenId);
    }
}