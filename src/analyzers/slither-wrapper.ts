/**
 * Slither static analyzer wrapper
 * Requires: pip3 install slither-analyzer
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import { Finding, Severity } from '../types';
import path from 'path';

const execAsync = promisify(exec);

interface SlitherResult {
  success: boolean;
  error: string | null;
  results: {
    detectors: Array<{
      check: string;
      impact: string;
      confidence: string;
      description: string;
      elements: Array<{
        type: string;
        name: string;
        source_mapping: {
          filename_relative: string;
          lines: number[];
        };
      }>;
    }>;
  };
}

/**
 * Run Slither analysis on contract files
 */
export async function runSlitherAnalysis(files: string[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Check if Slither is installed
  try {
    await execAsync('slither --version');
  } catch (error) {
    throw new Error('Slither not installed. Install with: pip3 install slither-analyzer');
  }

  // Run Slither on each file or directory
  const targets = new Set(files.map(f => path.dirname(f)));

  for (const target of targets) {
    try {
      logger.debug(`Running Slither on: ${target}`);

      // Run Slither with JSON output
      const { stdout } = await execAsync(
        `slither ${target} --json - --exclude-informational --exclude-low`,
        { maxBuffer: 10 * 1024 * 1024 }
      );

      // Parse Slither output
      const result: SlitherResult = JSON.parse(stdout);

      if (result.results && result.results.detectors) {
        for (const detector of result.results.detectors) {
          const finding = convertSlitherToFinding(detector);
          if (finding) {
            findings.push(finding);
          }
        }
      }

    } catch (error: any) {
      // Slither returns non-zero exit code when it finds issues
      // Try to parse output anyway
      if (error.stdout) {
        try {
          const result: SlitherResult = JSON.parse(error.stdout);
          if (result.results && result.results.detectors) {
            for (const detector of result.results.detectors) {
              const finding = convertSlitherToFinding(detector);
              if (finding) {
                findings.push(finding);
              }
            }
          }
        } catch {
          logger.debug(`Slither parsing failed for ${target}`);
        }
      } else {
        logger.warn(`Slither analysis failed for ${target}: ${error.message}`);
      }
    }
  }

  return findings;
}

/**
 * Convert Slither detector result to Finding
 */
function convertSlitherToFinding(detector: any): Finding | null {
  try {
    const severity = mapSlitherSeverity(detector.impact);
    const element = detector.elements?.[0];

    if (!element || !element.source_mapping) {
      return null;
    }

    const finding: Finding = {
      id: uuidv4(),
      contract: element.name || 'Unknown',
      source: 'static',
      rule_id: `SLITHER-${detector.check.toUpperCase().replace(/[^A-Z0-9]/g, '-')}`,
      title: formatTitle(detector.check),
      severity,
      impact: detector.impact.toLowerCase(),
      likelihood: detector.confidence.toLowerCase(),
      confidence: detector.confidence.toLowerCase() as any,
      description: detector.description,
      recommendation: getRecommendation(detector.check),
      files: [{
        path: element.source_mapping.filename_relative,
        line_start: element.source_mapping.lines[0] || 0,
        line_end: element.source_mapping.lines[element.source_mapping.lines.length - 1] || 0,
      }],
      evidence: [],
      tags: ['slither', detector.check],
      created_at: new Date().toISOString(),
    };

    return finding;
  } catch (error) {
    logger.debug('Failed to convert Slither result:', error);
    return null;
  }
}

/**
 * Map Slither impact/severity to our severity scale
 */
function mapSlitherSeverity(impact: string): Severity {
  const mapping: Record<string, Severity> = {
    'High': 'high',
    'Medium': 'medium',
    'Low': 'low',
    'Informational': 'informational',
  };

  return mapping[impact] || 'medium';
}

/**
 * Format check name to title
 */
function formatTitle(check: string): string {
  return check
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

/**
 * Get recommendation based on check type
 */
function getRecommendation(check: string): string {
  const recommendations: Record<string, string> = {
    'reentrancy-eth': 'Apply the checks-effects-interactions pattern or use ReentrancyGuard.',
    'reentrancy-no-eth': 'Apply the checks-effects-interactions pattern.',
    'tx-origin': 'Use msg.sender instead of tx.origin for authorization.',
    'unchecked-transfer': 'Check the return value of transfer/transferFrom.',
    'unchecked-send': 'Check the return value of send or use transfer.',
    'delegatecall-loop': 'Avoid delegatecall in loops.',
    'unprotected-upgrade': 'Add access control to upgrade functions.',
  };

  return recommendations[check] || 'Review and fix the identified issue according to best practices.';
}
