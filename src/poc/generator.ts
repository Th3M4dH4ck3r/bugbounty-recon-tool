/**
 * Advanced PoC generation logic
 */

import { Finding } from '../types';

/**
 * Generate exploit strategy based on vulnerability type
 */
export function generateExploitStrategy(finding: Finding): string {
  const category = finding.tags?.[0] || finding.rule_id;

  switch (category) {
    case 'reentrancy':
    case 'SC-REENT-01':
      return generateReentrancyStrategy(finding);

    case 'access-control':
    case 'SC-ACCESS-01':
      return generateAccessControlStrategy(finding);

    case 'integer-overflow':
    case 'SC-OVERFLOW-01':
      return generateOverflowStrategy(finding);

    case 'delegatecall':
    case 'SC-DELEGATECALL-01':
      return generateDelegatecallStrategy(finding);

    case 'tx-origin':
    case 'SC-TXORIGIN-01':
      return generateTxOriginStrategy(finding);

    default:
      return generateGenericStrategy(finding);
  }
}

function generateReentrancyStrategy(finding: Finding): string {
  return `
// REENTRANCY EXPLOIT STRATEGY
// This vulnerability allows an attacker to recursively call back into the
// vulnerable contract before the first invocation completes.
//
// Exploitation steps:
// 1. Deploy malicious contract with fallback/receive function
// 2. Call vulnerable function (e.g., withdraw) from malicious contract
// 3. In fallback, recursively call vulnerable function again
// 4. Drain funds before balance is updated
//
// Expected outcome: Multiple withdrawals with single balance check
`;
}

function generateAccessControlStrategy(finding: Finding): string {
  return `
// ACCESS CONTROL BYPASS STRATEGY
// This vulnerability allows unauthorized users to call privileged functions.
//
// Exploitation steps:
// 1. Identify the unprotected privileged function
// 2. Call function directly from attacker account
// 3. Verify unauthorized action was executed
//
// Expected outcome: Privileged operation executed without proper authorization
`;
}

function generateOverflowStrategy(finding: Finding): string {
  return `
// INTEGER OVERFLOW/UNDERFLOW STRATEGY
// This vulnerability allows manipulation of arithmetic operations to
// produce unexpected results due to integer wraparound.
//
// Exploitation steps:
// 1. Identify arithmetic operation without SafeMath
// 2. Craft input that causes overflow/underflow
// 3. Observe incorrect calculation result
//
// Expected outcome: Balance or value manipulation via overflow
`;
}

function generateDelegatecallStrategy(finding: Finding): string {
  return `
// DELEGATECALL VULNERABILITY STRATEGY
// This vulnerability allows attacker-controlled code to execute in the
// context of the vulnerable contract, potentially overwriting storage.
//
// Exploitation steps:
// 1. Deploy malicious contract with storage-modifying logic
// 2. Trigger delegatecall to malicious contract
// 3. Malicious code executes with victim contract's storage context
//
// Expected outcome: Complete contract takeover via storage manipulation
`;
}

function generateTxOriginStrategy(finding: Finding): string {
  return `
// TX.ORIGIN PHISHING STRATEGY
// This vulnerability allows attackers to bypass authentication checks
// by tricking legitimate users into calling a malicious contract.
//
// Exploitation steps:
// 1. Deploy phishing contract that calls vulnerable contract
// 2. Trick contract owner into sending transaction to phishing contract
// 3. Phishing contract calls vulnerable function
// 4. tx.origin check passes because it's the owner
//
// Expected outcome: Unauthorized action performed with owner's identity
`;
}

function generateGenericStrategy(finding: Finding): string {
  return `
// GENERIC VULNERABILITY EXPLOITATION
// Vulnerability: ${finding.title}
// Severity: ${finding.severity.toUpperCase()}
//
// Description: ${finding.description}
//
// Recommendation: ${finding.recommendation}
`;
}
