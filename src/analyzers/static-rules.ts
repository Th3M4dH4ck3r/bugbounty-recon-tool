/**
 * Custom static analysis rules for common vulnerabilities
 */

import { v4 as uuidv4 } from 'uuid';
import { readFile } from '../utils/file-utils';
import { logger } from '../utils/logger';
import { Finding, Rule, CodeLocation } from '../types';
import path from 'path';

/**
 * Built-in vulnerability detection rules
 */
const BUILTIN_RULES: Rule[] = [
  {
    id: 'SC-REENT-01',
    name: 'Reentrancy Vulnerability',
    description: 'State changes after external call - classic reentrancy pattern',
    severity: 'high',
    category: 'reentrancy',
    recommendation: 'Use checks-effects-interactions pattern. Update state before external calls or use ReentrancyGuard.',
    references: ['https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/'],
    check: (context: any) => {
      // Detect pattern: external call followed by state change
      return /\.call\{value:/.test(context.code) &&
             /balances\[.*\]\s*[-+]=/.test(context.code);
    },
  },
  {
    id: 'SC-ACCESS-01',
    name: 'Missing Access Control',
    description: 'Function lacks access control modifier',
    severity: 'high',
    category: 'access-control',
    recommendation: 'Add access control modifiers like onlyOwner or use OpenZeppelin AccessControl.',
    references: ['https://docs.openzeppelin.com/contracts/4.x/access-control'],
    check: (context: any) => {
      // Detect public/external functions with sensitive operations without modifiers
      const hasSensitiveOp = /selfdestruct|transfer\(|call\{value:|delegatecall/.test(context.code);
      const hasModifier = /onlyOwner|onlyAdmin|require\s*\(\s*msg\.sender\s*==/.test(context.code);
      return hasSensitiveOp && !hasModifier;
    },
  },
  {
    id: 'SC-UNCHECKED-01',
    name: 'Unchecked External Call',
    description: 'Result of external call is not checked',
    severity: 'medium',
    category: 'unchecked-call',
    recommendation: 'Check return value of external calls or use transfer() instead of call().',
    references: ['https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/'],
    check: (context: any) => {
      // Detect unchecked .call()
      return /\.call\(/.test(context.code) &&
             !/bool\s+\w+\s*=.*\.call\(/.test(context.code) &&
             !/require\s*\(.*\.call\(/.test(context.code);
    },
  },
  {
    id: 'SC-OVERFLOW-01',
    name: 'Integer Overflow/Underflow',
    description: 'Arithmetic operations without overflow protection (Solidity < 0.8.0)',
    severity: 'high',
    category: 'integer-overflow',
    recommendation: 'Use Solidity 0.8.0+ with built-in overflow checks or SafeMath library.',
    references: ['https://docs.soliditylang.org/en/v0.8.0/080-breaking-changes.html'],
    check: (context: any) => {
      // Check for old Solidity version and arithmetic
      const oldVersion = /pragma solidity \^?0\.[0-7]\./.test(context.code);
      const hasArithmetic = /\*|\+|-/.test(context.code) && !/SafeMath/.test(context.code);
      return oldVersion && hasArithmetic;
    },
  },
  {
    id: 'SC-TXORIGIN-01',
    name: 'tx.origin Authentication',
    description: 'Using tx.origin for authorization is vulnerable to phishing',
    severity: 'medium',
    category: 'tx-origin',
    recommendation: 'Use msg.sender instead of tx.origin for authentication.',
    references: ['https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/tx-origin/'],
    check: (context: any) => {
      return /tx\.origin/.test(context.code) && /require|if/.test(context.code);
    },
  },
  {
    id: 'SC-DELEGATECALL-01',
    name: 'Unsafe Delegatecall',
    description: 'Delegatecall to user-controlled address',
    severity: 'critical',
    category: 'delegatecall',
    recommendation: 'Never delegatecall to user-controlled addresses. Use a whitelist if needed.',
    references: ['https://consensys.github.io/smart-contract-best-practices/attacks/delegatecall/'],
    check: (context: any) => {
      return /delegatecall/.test(context.code);
    },
  },
  {
    id: 'SC-SELFDESTRUCT-01',
    name: 'Unprotected Selfdestruct',
    description: 'Selfdestruct without access control',
    severity: 'critical',
    category: 'selfdestruct',
    recommendation: 'Add strict access control to selfdestruct functions.',
    references: [],
    check: (context: any) => {
      const hasSelfdestruct = /selfdestruct/.test(context.code);
      const hasModifier = /onlyOwner|require\s*\(\s*msg\.sender/.test(context.code);
      return hasSelfdestruct && !hasModifier;
    },
  },
  {
    id: 'SC-TIMESTAMP-01',
    name: 'Block Timestamp Dependence',
    description: 'Using block.timestamp for critical logic',
    severity: 'low',
    category: 'timestamp',
    recommendation: 'Avoid using block.timestamp for critical logic. Consider block.number or external oracles.',
    references: ['https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/timestamp-dependence/'],
    check: (context: any) => {
      return /block\.timestamp/.test(context.code) && /require|if/.test(context.code);
    },
  },
];

/**
 * Run static rule analysis on contract files
 */
export async function runStaticRules(files: string[], customRulesPath?: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Load custom rules if provided
  let rules = [...BUILTIN_RULES];
  if (customRulesPath) {
    try {
      const customRules = await loadCustomRules(customRulesPath);
      rules = [...rules, ...customRules];
      logger.debug(`Loaded ${customRules.length} custom rules`);
    } catch (error: any) {
      logger.warn(`Failed to load custom rules: ${error.message}`);
    }
  }

  // Analyze each file
  for (const filePath of files) {
    try {
      const sourceCode = await readFile(filePath);
      const fileFindings = await analyzeFile(filePath, sourceCode, rules);
      findings.push(...fileFindings);
    } catch (error: any) {
      logger.error(`Failed to analyze ${filePath}:`, error.message);
    }
  }

  return findings;
}

/**
 * Analyze a single file with all rules
 */
async function analyzeFile(filePath: string, sourceCode: string, rules: Rule[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  const contractName = extractContractName(sourceCode);

  // Split into functions for better context
  const functions = extractFunctions(sourceCode);

  for (const rule of rules) {
    if (rule.enabled === false) continue;

    // Check each function
    for (const func of functions) {
      const context = {
        code: func.code,
        name: func.name,
        filePath,
        sourceCode,
      };

      try {
        if (rule.check(context)) {
          const location = findLocationInSource(sourceCode, func.code);

          const finding: Finding = {
            id: uuidv4(),
            contract: contractName || path.basename(filePath, '.sol'),
            source: 'static',
            rule_id: rule.id,
            title: rule.name,
            severity: rule.severity,
            impact: getImpactDescription(rule.severity),
            likelihood: 'medium',
            confidence: 'medium',
            description: rule.description,
            recommendation: rule.recommendation,
            files: [{
              path: filePath,
              line_start: location.line_start,
              line_end: location.line_end,
              snippet: func.code.split('\n').slice(0, 10).join('\n'),
            }],
            evidence: [],
            tags: [rule.category],
            references: rule.references,
            created_at: new Date().toISOString(),
          };

          findings.push(finding);
        }
      } catch (error: any) {
        logger.debug(`Rule ${rule.id} check failed:`, error.message);
      }
    }
  }

  return findings;
}

/**
 * Extract functions from source code
 */
function extractFunctions(sourceCode: string): Array<{ name: string; code: string }> {
  const functions: Array<{ name: string; code: string }> = [];

  // Match function definitions
  const functionRegex = /function\s+(\w+)\s*\([^)]*\)[^{]*\{[^}]*\}/gs;
  let match;

  while ((match = functionRegex.exec(sourceCode)) !== null) {
    functions.push({
      name: match[1],
      code: match[0],
    });
  }

  return functions;
}

/**
 * Extract contract name
 */
function extractContractName(sourceCode: string): string | null {
  const match = sourceCode.match(/contract\s+(\w+)/);
  return match ? match[1] : null;
}

/**
 * Find line numbers for code snippet in source
 */
function findLocationInSource(sourceCode: string, snippet: string): CodeLocation {
  const lines = sourceCode.split('\n');
  const snippetFirstLine = snippet.split('\n')[0].trim();

  let lineStart = 0;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim().includes(snippetFirstLine)) {
      lineStart = i + 1;
      break;
    }
  }

  const lineEnd = lineStart + snippet.split('\n').length;

  return {
    path: '',
    line_start: lineStart,
    line_end: lineEnd,
  };
}

/**
 * Get impact description based on severity
 */
function getImpactDescription(severity: string): string {
  const impacts: Record<string, string> = {
    critical: 'Complete loss of funds or contract control',
    high: 'Significant loss of funds or compromise of contract functionality',
    medium: 'Limited loss of funds or degraded functionality',
    low: 'Minor issues or potential for future vulnerabilities',
    informational: 'Code quality or best practice violations',
  };

  return impacts[severity] || 'Unknown impact';
}

/**
 * Load custom rules from file
 */
async function loadCustomRules(rulesPath: string): Promise<Rule[]> {
  // TODO: Implement custom rule loading from YAML/JSON
  // For now, return empty array
  logger.debug(`Custom rules loading not yet implemented for: ${rulesPath}`);
  return [];
}
