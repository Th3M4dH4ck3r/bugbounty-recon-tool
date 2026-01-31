/**
 * Security analyzers - static, dynamic, and symbolic analysis
 */

import { logger } from '../utils/logger';
import { Finding } from '../types';
import { runStaticRules } from './static-rules';
import { runSlitherAnalysis } from './slither-wrapper';
import { runMythrilAnalysis } from './mythril-wrapper';

export interface AnalyzerOptions {
  files: string[];
  rules?: string;
  enableSlither?: boolean;
  enableMythril?: boolean;
  timeout?: number;
}

/**
 * Run static analysis on contract files
 */
export async function runStaticAnalysis(options: AnalyzerOptions): Promise<Finding[]> {
  const allFindings: Finding[] = [];

  logger.info(`Analyzing ${options.files.length} file(s)...`);

  // 1. Run custom static rules (always enabled)
  try {
    logger.debug('Running custom static rules...');
    const ruleFindings = await runStaticRules(options.files, options.rules);
    allFindings.push(...ruleFindings);
    logger.info(`Custom rules: ${ruleFindings.length} finding(s)`);
  } catch (error: any) {
    logger.error('Custom rules analysis failed:', error.message);
  }

  // 2. Run Slither (optional)
  if (options.enableSlither) {
    try {
      logger.debug('Running Slither analysis...');
      const slitherFindings = await runSlitherAnalysis(options.files);
      allFindings.push(...slitherFindings);
      logger.info(`Slither: ${slitherFindings.length} finding(s)`);
    } catch (error: any) {
      logger.warn('Slither analysis failed:', error.message);
      logger.info('Install Slither: pip3 install slither-analyzer');
    }
  }

  // 3. Run Mythril (optional)
  if (options.enableMythril) {
    try {
      logger.debug('Running Mythril symbolic analysis...');
      const mythrilFindings = await runMythrilAnalysis(options.files, options.timeout);
      allFindings.push(...mythrilFindings);
      logger.info(`Mythril: ${mythrilFindings.length} finding(s)`);
    } catch (error: any) {
      logger.warn('Mythril analysis failed:', error.message);
      logger.info('Install Mythril: pipx install mythril');
    }
  }

  // Deduplicate findings by rule_id and location
  const uniqueFindings = deduplicateFindings(allFindings);

  logger.info(`Total unique findings: ${uniqueFindings.length}`);
  return uniqueFindings;
}

/**
 * Deduplicate findings based on rule_id and location
 */
function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const unique: Finding[] = [];

  for (const finding of findings) {
    const key = `${finding.rule_id}:${finding.contract}:${finding.files[0]?.line_start || 0}`;

    if (!seen.has(key)) {
      seen.add(key);
      unique.push(finding);
    }
  }

  return unique;
}

export * from './static-rules';
export * from './slither-wrapper';
export * from './mythril-wrapper';
export * from './rule-engine';
