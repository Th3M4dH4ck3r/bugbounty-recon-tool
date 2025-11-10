/**
 * Proof of Concept (PoC) generator
 * Automatically generates exploit scripts from findings
 */

import path from 'path';
import { Finding, ProofOfConcept, PocType } from '../types';
import { writeFile, ensureDir } from '../utils/file-utils';
import { log } from '../utils/logger';
import { generateHardhatPoc } from './templates/hardhat-template';
import { generateFoundryPoc } from './templates/foundry-template';
import { sanitizeFilename } from '../utils/file-utils';

export interface PocOptions {
  outputDir: string;
  type: PocType;
  dryRun?: boolean;
}

/**
 * Generate PoC from a finding
 */
export async function generatePoc(
  finding: Finding,
  options: PocOptions
): Promise<ProofOfConcept> {
  log.info(`Generating ${options.type} PoC for: ${finding.title}`);

  await ensureDir(options.outputDir);

  // Generate PoC based on type
  let pocContent: string;
  let fileExtension: string;

  switch (options.type) {
    case 'hardhat-script':
      pocContent = generateHardhatPoc(finding);
      fileExtension = 'js';
      break;

    case 'foundry-test':
      pocContent = generateFoundryPoc(finding);
      fileExtension = 'sol';
      break;

    case 'brownie-script':
      pocContent = generateHardhatPoc(finding); // Use Hardhat template for now
      fileExtension = 'py';
      break;

    case 'typescript':
      pocContent = generateHardhatPoc(finding); // Use Hardhat template for now
      fileExtension = 'ts';
      break;

    case 'python':
      pocContent = generateHardhatPoc(finding); // Use Hardhat template for now
      fileExtension = 'py';
      break;

    default:
      throw new Error(`Unsupported PoC type: ${options.type}`);
  }

  // Create filename
  const filename = `${sanitizeFilename(finding.rule_id)}_${sanitizeFilename(finding.contract)}.${fileExtension}`;
  const filePath = path.join(options.outputDir, filename);

  // Write PoC file
  await writeFile(filePath, pocContent);

  log.success(`PoC generated: ${filePath}`);

  const poc: ProofOfConcept = {
    path: filePath,
    type: options.type,
    simulated: true, // All PoCs are simulated by default
    description: `Proof of concept for ${finding.title}`,
    steps: extractStepsFromPoc(pocContent),
  };

  return poc;
}

/**
 * Extract steps from PoC code comments
 */
function extractStepsFromPoc(pocContent: string): string[] {
  const steps: string[] = [];
  const lines = pocContent.split('\n');

  for (const line of lines) {
    // Look for numbered steps in comments
    const match = line.match(/\/\/\s*(\d+\.|Step \d+:)\s*(.+)/i);
    if (match) {
      steps.push(match[2].trim());
    }
  }

  return steps;
}

export * from './generator';
