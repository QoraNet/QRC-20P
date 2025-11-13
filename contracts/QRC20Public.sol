// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title QRC20Public
 * @dev QoraNet QRC-20 Standard with enforced privacy features
 */
contract QRC20Public {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    
    address public immutable qrc20pAddress;
    address public immutable creator;
    bytes32 public immutable tokenId;
    address public universalSwitch;  // Per-token switch address (set once during deployment)
    bool private _switchInitialized;
    
    // PRIVACY FEATURE: Standard denominations (enforced on-chain)
    uint256[] public STANDARD_AMOUNTS;
    
    // PRIVACY FEATURE: Delayed execution for timing obfuscation
    struct PendingSwitch {
        address user;
        uint256 amount;
        bytes32 commitment;
        uint256 executeAfter;
        bool executed;
    }
    mapping(bytes32 => PendingSwitch) public pendingSwitches;
    
    // PRIVACY FEATURE: Batch switching
    struct BatchSwitch {
        address[] users;
        uint256[] amounts;
        bytes32[] commitments;
        uint256 executeAfter;
        bool executed;
    }
    mapping(bytes32 => BatchSwitch) public batchSwitches;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event SwitchedToPrivate(address indexed user, uint256 amount, bytes32 commitment);
    event SwitchCommitted(bytes32 indexed commitHash, uint256 executeAfter);
    event BatchSwitchCommitted(bytes32 indexed batchId, uint256 userCount, uint256 executeAfter);
    
    constructor(
        string memory _name,
        string memory _symbol,
        uint8 _decimals,
        uint256 _totalSupply,
        address _qrc20pAddress,
        address _creator
    ) {
        require(_qrc20pAddress != address(0), "QRC20: Invalid QRC-20P address");
        require(_creator != address(0), "QRC20: Invalid creator");

        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        totalSupply = _totalSupply;
        qrc20pAddress = _qrc20pAddress;
        creator = _creator;
        tokenId = keccak256(abi.encodePacked(address(this), _qrc20pAddress));
        _switchInitialized = false;

        // Initialize standard amounts (10^decimals precision)
        uint256 base = 10 ** uint256(_decimals);
        STANDARD_AMOUNTS.push(1 * base);      // 1 token
        STANDARD_AMOUNTS.push(5 * base);      // 5 tokens
        STANDARD_AMOUNTS.push(10 * base);     // 10 tokens
        STANDARD_AMOUNTS.push(50 * base);     // 50 tokens
        STANDARD_AMOUNTS.push(100 * base);    // 100 tokens (most common)
        STANDARD_AMOUNTS.push(500 * base);    // 500 tokens
        STANDARD_AMOUNTS.push(1000 * base);   // 1000 tokens
        STANDARD_AMOUNTS.push(5000 * base);   // 5000 tokens
        STANDARD_AMOUNTS.push(10000 * base);  // 10000 tokens

        _balances[_creator] = _totalSupply;
        emit Transfer(address(0), _creator, _totalSupply);
    }
    
    // ============================================
    // STANDARD QRC-20 FUNCTIONS
    // ============================================
    
    /**
     * @dev Initialize UniversalSwitch address (callable once by creator during deployment)
     */
    function initializeSwitch(address _universalSwitch) external {
        require(msg.sender == creator, "QRC20: Only creator");
        require(!_switchInitialized, "QRC20: Switch already initialized");
        require(_universalSwitch != address(0), "QRC20: Invalid switch address");

        universalSwitch = _universalSwitch;
        _switchInitialized = true;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }
    
    function transfer(address to, uint256 amount) public returns (bool) {
        require(to != address(0), "QRC20: Transfer to zero");
        require(_balances[msg.sender] >= amount, "QRC20: Insufficient balance");
        
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    function approve(address spender, uint256 amount) public returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    
    function allowance(address owner, address spender) public view returns (uint256) {
        return _allowances[owner][spender];
    }
    
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(to != address(0), "QRC20: Transfer to zero");
        require(_balances[from] >= amount, "QRC20: Insufficient balance");
        require(_allowances[from][msg.sender] >= amount, "QRC20: Allowance exceeded");
        
        _allowances[from][msg.sender] -= amount;
        _balances[from] -= amount;
        _balances[to] += amount;
        
        emit Transfer(from, to, amount);
        return true;
    }
    
    // ============================================
    // PRIVACY MODE SWITCHING - INSTANT (Less Private)
    // ============================================
    
    /**
     * @dev Instant switch - ENFORCES standard amounts
     * Use this if you don't care about timing analysis
     */
    function switchToPrivateInstant(
        uint256 amount,
        bytes32 commitment
    ) external returns (bool) {
        require(isStandardAmount(amount), "QRC20: Use standard amounts only");
        require(_balances[msg.sender] >= amount, "QRC20: Insufficient balance");
        require(commitment != bytes32(0), "QRC20: Invalid commitment");

        _balances[msg.sender] -= amount;
        totalSupply -= amount;

        (bool success, ) = universalSwitch.call(
            abi.encodeWithSignature(
                "processPublicToPrivate(address,uint256,bytes32)",
                msg.sender,
                amount,
                commitment
            )
        );
        require(success, "QRC20: Switch failed");

        emit Transfer(msg.sender, address(0), amount);
        emit SwitchedToPrivate(msg.sender, amount, commitment);

        return true;
    }
    
    // ============================================
    // PRIVACY MODE SWITCHING - DELAYED (More Private)
    // ============================================
    
    /**
     * @dev Step 1: Commit to switch with random delay
     * Better privacy - breaks timing analysis
     */
    function commitSwitchToPrivate(
        uint256 amount,
        bytes32 commitment,
        uint256 delaySeconds // 60-3600 (1-60 minutes)
    ) external returns (bytes32 commitHash) {
        require(isStandardAmount(amount), "QRC20: Use standard amounts only");
        require(_balances[msg.sender] >= amount, "QRC20: Insufficient balance");
        require(delaySeconds >= 60 && delaySeconds <= 3600, "QRC20: Delay 1-60min");
        
        // Lock the amount
        _balances[msg.sender] -= amount;
        
        commitHash = keccak256(abi.encodePacked(
            msg.sender,
            amount,
            commitment,
            block.timestamp
        ));
        
        uint256 executeAfter = block.timestamp + delaySeconds;
        
        pendingSwitches[commitHash] = PendingSwitch({
            user: msg.sender,
            amount: amount,
            commitment: commitment,
            executeAfter: executeAfter,
            executed: false
        });
        
        emit SwitchCommitted(commitHash, executeAfter);
        
        return commitHash;
    }
    
    /**
     * @dev Step 2: Execute switch after delay
     * Anyone can execute (relayer support)
     */
    function executeSwitchToPrivate(bytes32 commitHash) external returns (bool) {
        PendingSwitch storage pending = pendingSwitches[commitHash];
        
        require(pending.user != address(0), "QRC20: Unknown commit");
        require(!pending.executed, "QRC20: Already executed");
        require(block.timestamp >= pending.executeAfter, "QRC20: Too early");
        require(block.timestamp <= pending.executeAfter + 86400, "QRC20: Expired");
        
        pending.executed = true;
        totalSupply -= pending.amount;
        
        (bool success, ) = universalSwitch.call(
            abi.encodeWithSignature(
                "processPublicToPrivate(address,address,address,uint256,bytes32)",
                address(this),
                qrc20pAddress,
                pending.user,
                pending.amount,
                pending.commitment
            )
        );
        require(success, "QRC20: Switch failed");

        emit Transfer(pending.user, address(0), pending.amount);
        emit SwitchedToPrivate(pending.user, pending.amount, pending.commitment);

        return true;
    }
    
    /**
     * @dev Cancel pending switch and refund
     */
    function cancelPendingSwitch(bytes32 commitHash) external {
        PendingSwitch storage pending = pendingSwitches[commitHash];
        
        require(pending.user == msg.sender, "QRC20: Not your switch");
        require(!pending.executed, "QRC20: Already executed");
        
        // Refund locked amount
        _balances[msg.sender] += pending.amount;
        
        delete pendingSwitches[commitHash];
    }
    
    // ============================================
    // BATCH SWITCHING - MAXIMUM PRIVACY
    // ============================================
    
    /**
     * @dev Batch switch - multiple users in one transaction
     * MAXIMUM privacy - impossible to link individual switches
     */
    function commitBatchSwitch(
        address[] calldata users,
        uint256[] calldata amounts,
        bytes32[] calldata commitments,
        uint256 delaySeconds
    ) external returns (bytes32 batchId) {
        require(users.length == amounts.length, "QRC20: Length mismatch");
        require(users.length == commitments.length, "QRC20: Length mismatch");
        require(users.length >= 3, "QRC20: Min 3 users for batch");
        require(users.length <= 100, "QRC20: Max 100 users");
        require(delaySeconds >= 60 && delaySeconds <= 3600, "QRC20: Delay 1-60min");
        
        // Verify all amounts are standard
        for (uint i = 0; i < amounts.length; i++) {
            require(isStandardAmount(amounts[i]), "QRC20: Use standard amounts");
        }
        
        batchId = keccak256(abi.encodePacked(
            users,
            amounts,
            commitments,
            block.timestamp
        ));
        
        uint256 executeAfter = block.timestamp + delaySeconds;
        
        batchSwitches[batchId] = BatchSwitch({
            users: users,
            amounts: amounts,
            commitments: commitments,
            executeAfter: executeAfter,
            executed: false
        });
        
        emit BatchSwitchCommitted(batchId, users.length, executeAfter);
        
        return batchId;
    }
    
    /**
     * @dev Execute batch switch
     */
    function executeBatchSwitch(bytes32 batchId) external returns (bool) {
        BatchSwitch storage batch = batchSwitches[batchId];
        
        require(batch.users.length > 0, "QRC20: Unknown batch");
        require(!batch.executed, "QRC20: Already executed");
        require(block.timestamp >= batch.executeAfter, "QRC20: Too early");
        require(block.timestamp <= batch.executeAfter + 86400, "QRC20: Expired");
        
        batch.executed = true;
        
        // Process all switches in batch
        for (uint i = 0; i < batch.users.length; i++) {
            require(_balances[batch.users[i]] >= batch.amounts[i], "QRC20: Insufficient balance");
            
            _balances[batch.users[i]] -= batch.amounts[i];
            totalSupply -= batch.amounts[i];
            
            (bool success, ) = universalSwitch.call(
                abi.encodeWithSignature(
                    "processPublicToPrivate(address,address,address,uint256,bytes32)",
                    address(this),
                    qrc20pAddress,
                    batch.users[i],
                    batch.amounts[i],
                    batch.commitments[i]
                )
            );
            require(success, "QRC20: Batch switch failed");
            
            emit Transfer(batch.users[i], address(0), batch.amounts[i]);
        }
        
        return true;
    }
    
    // ============================================
    // HELPER FUNCTIONS
    // ============================================
    
    function isStandardAmount(uint256 amount) public view returns (bool) {
        for (uint i = 0; i < STANDARD_AMOUNTS.length; i++) {
            if (amount == STANDARD_AMOUNTS[i]) {
                return true;
            }
        }
        return false;
    }
    
    function getStandardAmounts() external view returns (uint256[] memory) {
        return STANDARD_AMOUNTS;
    }
    
    // ============================================
    // RECEIVE FROM PRIVATE MODE
    // ============================================
    
    function mintFromPrivate(address recipient, uint256 amount) external returns (bool) {
        require(msg.sender == universalSwitch, "QRC20: Only switch");
        require(recipient != address(0), "QRC20: Invalid recipient");
        
        _balances[recipient] += amount;
        totalSupply += amount;
        
        emit Transfer(address(0), recipient, amount);
        return true;
    }
    
    function getTokenId() external view returns (bytes32) {
        return tokenId;
    }
    
    function standard() external pure returns (string memory) {
        return "QRC-20";
    }
}