/**
 * Mythril symbolic analyzer wrapper
 * Requires: pipx install mythril
 *
 * Mythril provides symbolic execution analysis for smart contracts.
 * It's the open-source engine that powers MythX.
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import { Finding, Severity } from '../types';
import path from 'path';

const execAsync = promisify(exec);

interface MythrilIssue {
  address: number;
  contract: string;
  description: {
    head: string;
    tail: string;
  };
  extra: Record<string, any>;
  function: string;
  lineno: number;
  max_gas_used?: number;
  min_gas_used?: number;
  severity: string;
  'swc-id': string;
  title: string;
  filename?: string;
}

interface MythrilResult {
  success: boolean;
  error: string | null;
  issues: MythrilIssue[];
}

/**
 * Run Mythril analysis on contract files
 */
export async function runMythrilAnalysis(files: string[], timeout: number = 300): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Check if Mythril is installed
  try {
    await execAsync('myth version');
  } catch (error) {
    throw new Error('Mythril not installed. Install with: pipx install mythril');
  }

  // Run Mythril on each file
  for (const file of files) {
    // Skip non-Solidity files
    if (!file.endsWith('.sol')) {
      continue;
    }

    try {
      logger.debug(`Running Mythril on: ${file}`);

      // Run Mythril with JSON output
      // --execution-timeout limits symbolic execution time per path
      // -o json outputs in JSON format
      const { stdout, stderr } = await execAsync(
        `myth analyze ${file} -o json --execution-timeout ${timeout}`,
        {
          maxBuffer: 10 * 1024 * 1024,
          timeout: (timeout + 60) * 1000, // Add buffer to execution timeout
        }
      );

      // Parse Mythril output
      if (stdout.trim()) {
        const result: MythrilResult = JSON.parse(stdout);

        if (result.success && result.issues) {
          for (const issue of result.issues) {
            const finding = convertMythrilToFinding(issue, file);
            if (finding) {
              findings.push(finding);
            }
          }
        }
      }

    } catch (error: any) {
      // Mythril may return non-zero when it finds issues
      if (error.stdout) {
        try {
          const result: MythrilResult = JSON.parse(error.stdout);
          if (result.issues) {
            for (const issue of result.issues) {
              const finding = convertMythrilToFinding(issue, file);
              if (finding) {
                findings.push(finding);
              }
            }
          }
        } catch {
          logger.debug(`Mythril parsing failed for ${file}`);
        }
      } else if (error.killed) {
        logger.warn(`Mythril timed out analyzing ${file}`);
      } else {
        logger.warn(`Mythril analysis failed for ${file}: ${error.message}`);
      }
    }
  }

  return findings;
}

/**
 * Convert Mythril issue to Finding format
 */
function convertMythrilToFinding(issue: MythrilIssue, filePath: string): Finding | null {
  try {
    const severity = mapMythrilSeverity(issue.severity);
    const swcId = issue['swc-id'] || 'UNKNOWN';

    const finding: Finding = {
      id: uuidv4(),
      contract: issue.contract || path.basename(filePath, '.sol'),
      source: 'symbolic',
      rule_id: `MYTHRIL-${swcId}`,
      title: issue.title || issue.description?.head || 'Unknown Issue',
      severity,
      impact: severity,
      likelihood: 'medium',
      confidence: 'medium',
      description: formatDescription(issue.description),
      recommendation: getRecommendation(swcId),
      files: [{
        path: issue.filename || filePath,
        line_start: issue.lineno || 0,
        line_end: issue.lineno || 0,
      }],
      evidence: issue.function ? [{
        type: 'trace',
        description: `Affected function: ${issue.function}`,
        content: issue.extra ? JSON.stringify(issue.extra, null, 2) : undefined,
      }] : [],
      tags: ['mythril', swcId, 'symbolic-execution'],
      references: [`https://swcregistry.io/docs/${swcId}`],
      created_at: new Date().toISOString(),
    };

    return finding;
  } catch (error) {
    logger.debug('Failed to convert Mythril result:', error);
    return null;
  }
}

/**
 * Map Mythril severity to our severity scale
 */
function mapMythrilSeverity(severity: string): Severity {
  const mapping: Record<string, Severity> = {
    'High': 'high',
    'Medium': 'medium',
    'Low': 'low',
    'Informational': 'informational',
  };

  return mapping[severity] || 'medium';
}

/**
 * Format Mythril description
 */
function formatDescription(desc: { head: string; tail: string } | undefined): string {
  if (!desc) return 'No description available.';
  return `${desc.head}\n\n${desc.tail}`;
}

/**
 * Get recommendation based on SWC ID
 */
function getRecommendation(swcId: string): string {
  const recommendations: Record<string, string> = {
    'SWC-101': 'Use SafeMath library or Solidity 0.8+ for automatic overflow checks.',
    'SWC-104': 'Ensure unchecked external calls cannot be exploited. Check return values.',
    'SWC-105': 'Use ReentrancyGuard or apply checks-effects-interactions pattern.',
    'SWC-106': 'Protect selfdestruct with proper access control.',
    'SWC-107': 'Apply the checks-effects-interactions pattern to prevent reentrancy.',
    'SWC-110': 'Do not rely on assert() for input validation. Use require() instead.',
    'SWC-111': 'Avoid deprecated functions. Use current Solidity equivalents.',
    'SWC-112': 'Avoid delegatecall to untrusted contracts.',
    'SWC-113': 'Avoid using multiple if statements when else-if is more appropriate.',
    'SWC-114': 'Only use tx.origin for denying external contracts.',
    'SWC-115': 'Use msg.sender instead of tx.origin for authorization.',
    'SWC-116': 'Avoid block.timestamp for randomness. Use Chainlink VRF or similar.',
    'SWC-120': 'Add checks for weak randomness sources.',
    'SWC-123': 'Avoid require() with empty message strings.',
    'SWC-124': 'Ensure proper access control on sensitive functions.',
    'SWC-125': 'Use fixed-point arithmetic or scale decimals properly.',
    'SWC-126': 'Ensure value passed matches expected amount.',
    'SWC-127': 'Handle arbitrary jump destinations carefully.',
    'SWC-128': 'Avoid using block.number for time-sensitive operations.',
    'SWC-129': 'Ensure type conversions preserve intended values.',
    'SWC-131': 'Avoid unused variables to reduce bytecode size and confusion.',
    'SWC-132': 'Handle unexpected ether properly with receive/fallback functions.',
    'SWC-134': 'Add proper error messages to require statements.',
    'SWC-135': 'Ensure all code paths return a value.',
    'SWC-136': 'Check for unencrypted private data on-chain.',
  };

  return recommendations[swcId] || `Review and fix the ${swcId} issue according to SWC Registry guidelines.`;
}
