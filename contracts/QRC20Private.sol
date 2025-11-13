// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title QRC20P
 * @dev QoraNet QRC-20P with enforced privacy features
 */
contract QRC20Private {
    address public qrc20PublicAddress;  // Set during initialization
    address public immutable creator;
    address public universalSwitch;  // Per-token switch address (set once during deployment)
    bool private _switchInitialized;
    bytes32 public tokenId;  // Calculated after both contracts deployed

    address public constant PALLET_BRIDGE = address(0x73);  // Substrate privacy bridge
    address public constant ZK_VERIFIER = address(0x72);
    address public constant POSEIDON_HASH = address(0x71);
    
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public nullifiers;
    mapping(bytes32 => uint256) public commitmentIndex;
    uint256 public nextIndex;
    uint256 private _shieldedSupply;
    
    // PRIVACY: Standard denominations (must match QRC20)
    uint256[] public STANDARD_AMOUNTS;
    
    // PRIVACY: Delayed unshielding
    struct PendingUnshield {
        bytes32 nullifier;
        address recipient;
        uint256 amount;
        uint256 executeAfter;
        bool executed;
    }
    mapping(bytes32 => PendingUnshield) public pendingUnshields;
    
    mapping(bytes32 => bool) public knownRoots;
    bytes32[] public rootHistory;
    uint256 public constant ROOT_HISTORY_SIZE = 100;
    
    event CommitmentAdded(bytes32 indexed commitment, uint256 leafIndex);
    event NullifierUsed(bytes32 indexed nullifier);
    event PrivateTransfer(bytes32[] inputNullifiers, bytes32[] outputCommitments, bytes32 merkleRoot);
    event SwitchedToPublic(address indexed recipient, uint256 amount, bytes32 nullifier);
    event UnshieldCommitted(bytes32 indexed commitHash, uint256 executeAfter);
    
    constructor(
        address _creator,
        uint8 decimals
    ) {
        require(_creator != address(0), "QRC20P: Invalid creator");

        creator = _creator;
        _switchInitialized = false;
        // qrc20PublicAddress and tokenId will be set during initializeSwitch()

        // Initialize standard amounts (must match QRC20)
        uint256 base = 10 ** uint256(decimals);
        STANDARD_AMOUNTS.push(1 * base);
        STANDARD_AMOUNTS.push(5 * base);
        STANDARD_AMOUNTS.push(10 * base);
        STANDARD_AMOUNTS.push(50 * base);
        STANDARD_AMOUNTS.push(100 * base);
        STANDARD_AMOUNTS.push(500 * base);
        STANDARD_AMOUNTS.push(1000 * base);
        STANDARD_AMOUNTS.push(5000 * base);
        STANDARD_AMOUNTS.push(10000 * base);

        merkleRoot = bytes32(0);
        knownRoots[bytes32(0)] = true;
        rootHistory.push(bytes32(0));
    }
    
    // ============================================
    // INSTANT UNSHIELD (Less Private)
    // ============================================
    
    function switchToPublicInstant(
        bytes calldata proof,
        bytes32 nullifier,
        address recipient,
        uint256 amount,
        bytes32 root
    ) external returns (bool) {
        require(isStandardAmount(amount), "QRC20P: Use standard amounts");
        require(recipient != address(0), "QRC20P: Invalid recipient");
        require(!nullifiers[nullifier], "QRC20P: Nullifier used");
        require(knownRoots[root], "QRC20P: Unknown root");
        
        require(_verifyUnshieldProof(proof, nullifier, recipient, amount, root), "QRC20P: Invalid proof");
        
        nullifiers[nullifier] = true;
        _shieldedSupply -= amount;
        
        (bool success, ) = universalSwitch.call(
            abi.encodeWithSignature(
                "processPrivateToPublic(address,uint256,bytes32)",
                recipient,
                amount,
                nullifier
            )
        );
        require(success, "QRC20P: Switch failed");
        

        emit NullifierUsed(nullifier);
        emit SwitchedToPublic(recipient, amount, nullifier);

        return true;
    }
    
    // ============================================
    // DELAYED UNSHIELD (More Private)
    // ============================================
    
    function commitSwitchToPublic(
        bytes calldata proof,
        bytes32 nullifier,
        address recipient,
        uint256 amount,
        bytes32 root,
        uint256 delaySeconds
    ) external returns (bytes32 commitHash) {
        require(isStandardAmount(amount), "QRC20P: Use standard amounts");
        require(!nullifiers[nullifier], "QRC20P: Nullifier used");
        require(delaySeconds >= 60 && delaySeconds <= 3600, "QRC20P: Delay 1-60min");
        
        require(_verifyUnshieldProof(proof, nullifier, recipient, amount, root), "QRC20P: Invalid proof");
        
        commitHash = keccak256(abi.encodePacked(nullifier, recipient, amount, block.timestamp));
        
        pendingUnshields[commitHash] = PendingUnshield({
            nullifier: nullifier,
            recipient: recipient,
            amount: amount,
            executeAfter: block.timestamp + delaySeconds,
            executed: false
        });
        
        emit UnshieldCommitted(commitHash, block.timestamp + delaySeconds);
        
        return commitHash;
    }
    
    function executeSwitchToPublic(bytes32 commitHash) external returns (bool) {
        PendingUnshield storage pending = pendingUnshields[commitHash];
        
        require(pending.recipient != address(0), "QRC20P: Unknown commit");
        require(!pending.executed, "QRC20P: Already executed");
        require(block.timestamp >= pending.executeAfter, "QRC20P: Too early");
        require(block.timestamp <= pending.executeAfter + 86400, "QRC20P: Expired");
        require(!nullifiers[pending.nullifier], "QRC20P: Nullifier used");
        
        pending.executed = true;
        nullifiers[pending.nullifier] = true;
        _shieldedSupply -= pending.amount;
        
        (bool success, ) = universalSwitch.call(
            abi.encodeWithSignature(
                "processPrivateToPublic(address,uint256,bytes32)",
                pending.recipient,
                pending.amount,
                pending.nullifier
            )
        );
        require(success, "QRC20P: Switch failed");

        emit NullifierUsed(pending.nullifier);
        emit SwitchedToPublic(pending.recipient, pending.amount, pending.nullifier);

        return true;
    }
    
    // ============================================
    // PRIVATE TRANSFERS
    // ============================================
    
    function privateTransfer(
        bytes calldata proof,
        bytes32[] calldata inputNullifiers,
        bytes32[] calldata outputCommitments,
        bytes32 root
    ) external returns (bool) {
        require(inputNullifiers.length > 0 && inputNullifiers.length <= 16, "QRC20P: Invalid inputs");
        require(outputCommitments.length > 0 && outputCommitments.length <= 16, "QRC20P: Invalid outputs");
        require(knownRoots[root], "QRC20P: Unknown root");
        
        for (uint i = 0; i < inputNullifiers.length; i++) {
            require(!nullifiers[inputNullifiers[i]], "QRC20P: Nullifier used");
        }
        
        require(_verifyPrivateTransferProof(proof, inputNullifiers, outputCommitments, root), "QRC20P: Invalid proof");
        
        for (uint i = 0; i < inputNullifiers.length; i++) {
            nullifiers[inputNullifiers[i]] = true;
            emit NullifierUsed(inputNullifiers[i]);
        }
        
        for (uint i = 0; i < outputCommitments.length; i++) {
            _insertCommitment(outputCommitments[i]);
        }
        
        emit PrivateTransfer(inputNullifiers, outputCommitments, root);
        
        return true;
    }
    
    // ============================================
    // INITIALIZATION & SHIELDING
    // ============================================

    /**
     * @dev Initialize with QRC20Public address and UniversalSwitch (callable once by creator during deployment)
     */
    function initializeSwitch(address _qrc20Public, address _universalSwitch) external {
        require(msg.sender == creator, "QRC20P: Only creator");
        require(!_switchInitialized, "QRC20P: Switch already initialized");
        require(_qrc20Public != address(0), "QRC20P: Invalid public address");
        require(_universalSwitch != address(0), "QRC20P: Invalid switch address");

        qrc20PublicAddress = _qrc20Public;
        universalSwitch = _universalSwitch;
        tokenId = keccak256(abi.encodePacked(_qrc20Public, address(this)));
        _switchInitialized = true;
    }

    function shieldFromPublic(bytes32 commitment, uint256 amount) external returns (uint256) {
        require(msg.sender == universalSwitch, "QRC20P: Only switch");
        require(isStandardAmount(amount), "QRC20P: Use standard amounts");

        uint256 leafIndex = _insertCommitment(commitment);
        _shieldedSupply += amount;

        // Call Pallet Bridge (0x73) to register commitment in Substrate
        (bool success, ) = PALLET_BRIDGE.call(
            abi.encodeWithSignature(
                "addCommitment(bytes32)",
                commitment
            )
        );
        require(success, "QRC20P: Pallet commitment failed");

        return leafIndex;
    }
    
    // ============================================
    // INTERNAL
    // ============================================
    
    function _insertCommitment(bytes32 commitment) private returns (uint256) {
        uint256 leafIndex = nextIndex++;
        commitmentIndex[commitment] = leafIndex;
        
        bytes32 oldRoot = merkleRoot;
        
        (bool success, bytes memory result) = POSEIDON_HASH.staticcall(
            abi.encodePacked(oldRoot, commitment, leafIndex)
        );
        require(success, "QRC20P: Hash failed");
        merkleRoot = abi.decode(result, (bytes32));
        
        knownRoots[merkleRoot] = true;
        rootHistory.push(merkleRoot);
        
        if (rootHistory.length > ROOT_HISTORY_SIZE) {
            delete knownRoots[rootHistory[rootHistory.length - ROOT_HISTORY_SIZE - 1]];
        }
        
        emit CommitmentAdded(commitment, leafIndex);
        
        return leafIndex;
    }
    
    function _verifyUnshieldProof(
        bytes calldata proof,
        bytes32 nullifier,
        address recipient,
        uint256 amount,
        bytes32 root
    ) private view returns (bool) {
        bytes32[] memory publicInputs = new bytes32[](4);
        publicInputs[0] = root;
        publicInputs[1] = nullifier;
        publicInputs[2] = bytes32(uint256(uint160(recipient)));
        publicInputs[3] = bytes32(amount);
        
        (bool success, bytes memory result) = ZK_VERIFIER.staticcall(abi.encode(proof, publicInputs));
        return success && abi.decode(result, (bool));
    }
    
    function _verifyPrivateTransferProof(
        bytes calldata proof,
        bytes32[] calldata inputNullifiers,
        bytes32[] calldata outputCommitments,
        bytes32 root
    ) private view returns (bool) {
        bytes32[] memory publicInputs = new bytes32[](1 + inputNullifiers.length + outputCommitments.length);
        publicInputs[0] = root;
        
        for (uint i = 0; i < inputNullifiers.length; i++) {
            publicInputs[1 + i] = inputNullifiers[i];
        }
        
        for (uint i = 0; i < outputCommitments.length; i++) {
            publicInputs[1 + inputNullifiers.length + i] = outputCommitments[i];
        }
        
        (bool success, bytes memory result) = ZK_VERIFIER.staticcall(abi.encode(proof, publicInputs));
        return success && abi.decode(result, (bool));
    }
    
    function isStandardAmount(uint256 amount) public view returns (bool) {
        for (uint i = 0; i < STANDARD_AMOUNTS.length; i++) {
            if (amount == STANDARD_AMOUNTS[i]) {
                return true;
            }
        }
        return false;
    }
    
    function getMerkleRoot() external view returns (bytes32) {
        return merkleRoot;
    }
    
    function standard() external pure returns (string memory) {
        return "QRC-20P";
    }
}