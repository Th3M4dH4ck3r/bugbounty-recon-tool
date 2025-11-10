// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * @title VulnerableToken
 * @notice WARNING: This contract contains intentional vulnerabilities for testing.
 * DO NOT use in production.
 *
 * Additional vulnerabilities for comprehensive testing:
 * 1. Delegatecall to untrusted address
 * 2. Unprotected selfdestruct
 * 3. Timestamp dependence
 * 4. Front-running vulnerability in approve/transferFrom
 */
contract VulnerableToken {
    string public name = "Vulnerable Token";
    string public symbol = "VUL";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    address public owner;
    address public implementation;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 _initialSupply) {
        owner = msg.sender;
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
    }

    // Vulnerability 1: Delegatecall to user-controlled address
    function upgradeImplementation(address _implementation) public {
        // Missing access control AND delegatecall to untrusted address
        implementation = _implementation;
    }

    function executeUpgrade(bytes memory data) public {
        // Delegatecall allows the implementation to modify this contract's storage!
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    // Vulnerability 2: Unprotected selfdestruct
    function destroy() public {
        // Anyone can destroy the contract!
        selfdestruct(payable(msg.sender));
    }

    // Vulnerability 3: Timestamp dependence for critical logic
    function mintTimeLocked(uint256 amount) public {
        // Using block.timestamp for critical logic - miners can manipulate
        require(block.timestamp % 2 == 0, "Can only mint on even timestamps");
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }

    // Vulnerability 4: Classic ERC20 approve race condition
    function approve(address spender, uint256 value) public returns (bool) {
        // Should use increaseAllowance/decreaseAllowance to prevent front-running
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint256 value) public returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        require(balanceOf[from] >= value, "Insufficient balance");
        require(allowance[from][msg.sender] >= value, "Insufficient allowance");

        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;

        emit Transfer(from, to, value);
        return true;
    }
}
