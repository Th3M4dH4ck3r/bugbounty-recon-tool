/**
 * Report generation module
 */

import { Finding } from '../types';
import { logger } from '../utils/logger';
import { generateMarkdownReport } from './report-gen';

export interface ReportOptions {
  format: 'json' | 'markdown' | 'html' | 'pdf';
  outputPath: string;
  template?: string;
  includeEvidence?: boolean;
  includePocs?: boolean;
}

export interface ReportResult {
  path: string;
  format: string;
  findingsCount: number;
}

/**
 * Generate security report from findings
 */
export async function generateReport(
  findings: Finding[],
  options: ReportOptions
): Promise<ReportResult> {
  logger.info(`Generating ${options.format} report...`);

  let reportPath: string;

  switch (options.format) {
    case 'markdown':
      reportPath = await generateMarkdownReport(findings, options);
      break;

    case 'json':
      reportPath = await generateJsonReport(findings, options);
      break;

    case 'html':
      logger.warn('HTML report generation not yet implemented');
      reportPath = await generateMarkdownReport(findings, options);
      break;

    case 'pdf':
      logger.warn('PDF report generation not yet implemented');
      reportPath = await generateMarkdownReport(findings, options);
      break;

    default:
      throw new Error(`Unsupported report format: ${options.format}`);
  }

  return {
    path: reportPath,
    format: options.format,
    findingsCount: findings.length,
  };
}

/**
 * Generate JSON report
 */
async function generateJsonReport(
  findings: Finding[],
  options: ReportOptions
): Promise<string> {
  const { writeJson } = await import('../utils/file-utils');

  const report = {
    generated_at: new Date().toISOString(),
    findings_count: findings.length,
    severity_distribution: getSeverityDistribution(findings),
    findings,
  };

  await writeJson(options.outputPath, report);
  return options.outputPath;
}

/**
 * Get severity distribution
 */
function getSeverityDistribution(findings: Finding[]): Record<string, number> {
  const distribution: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };

  findings.forEach(finding => {
    distribution[finding.severity] = (distribution[finding.severity] || 0) + 1;
  });

  return distribution;
}

export * from './report-gen';
export * from './severity-scorer';
