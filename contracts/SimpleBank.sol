// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * @title SimpleBank
 * @notice WARNING: This contract contains intentional vulnerabilities for testing purposes.
 * DO NOT use in production.
 *
 * Vulnerabilities included:
 * 1. Reentrancy in withdraw()
 * 2. Missing access control on emergencyWithdraw()
 * 3. Unchecked external call result in transfer()
 * 4. Integer overflow in addInterest() (Solidity < 0.8.0)
 * 5. tx.origin authentication bypass in setOwner()
 */
contract SimpleBank {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalDeposits;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
    }

    // Vulnerability 1: Reentrancy - state update after external call
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update after external call - VULNERABLE!
        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        emit Withdrawal(msg.sender, amount);
    }

    function deposit() public payable {
        require(msg.value > 0, "Must deposit some ETH");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // Vulnerability 2: Missing access control - anyone can call
    function emergencyWithdraw() public {
        // Should have onlyOwner modifier!
        payable(msg.sender).transfer(address(this).balance);
    }

    // Vulnerability 3: Unchecked low-level call result
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;

        // Unchecked external call - result is ignored!
        to.call{value: 0}("");
    }

    // Vulnerability 4: Integer overflow (Solidity < 0.8.0)
    function addInterest(address user, uint256 rate) public {
        // Can overflow if balances[user] * rate > 2^256
        uint256 interest = balances[user] * rate;
        balances[user] += interest; // Potential overflow
        totalDeposits += interest;
    }

    // Vulnerability 5: tx.origin authentication - phishing vulnerability
    function setOwner(address newOwner) public {
        // Using tx.origin instead of msg.sender!
        require(tx.origin == owner, "Not owner");
        address oldOwner = owner;
        owner = newOwner;
        emit OwnerChanged(oldOwner, newOwner);
    }

    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }

    receive() external payable {
        deposit();
    }
}
