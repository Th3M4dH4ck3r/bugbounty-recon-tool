/**
 * Local filesystem collector
 */

import path from 'path';
import { findSolidityFiles, readFile, copy, ensureDir } from '../utils/file-utils';
import { logger } from '../utils/logger';
import { ContractInfo } from '../types';
import { CollectorOptions } from './index';

/**
 * Collect contracts from local filesystem
 */
export async function collectFromLocal(
  targetPath: string,
  options: CollectorOptions
): Promise<ContractInfo[]> {
  logger.info(`Collecting from local path: ${targetPath}`);

  // Find all Solidity files
  const files = await findSolidityFiles(targetPath);

  if (files.length === 0) {
    logger.warn('No Solidity files found in target directory');
    return [];
  }

  const contracts: ContractInfo[] = [];

  // Process each file
  for (const filePath of files) {
    try {
      const sourceCode = await readFile(filePath);
      const contractName = extractContractName(sourceCode) || path.basename(filePath, '.sol');

      const contract: ContractInfo = {
        name: contractName,
        path: filePath,
        source_code: sourceCode,
      };

      contracts.push(contract);

      // Copy to output directory if specified
      if (options.output) {
        await ensureDir(options.output);
        const destPath = path.join(options.output, path.basename(filePath));
        await copy(filePath, destPath);
        logger.debug(`Copied ${filePath} to ${destPath}`);
      }

    } catch (error: any) {
      logger.error(`Failed to process ${filePath}:`, error.message);
    }
  }

  logger.info(`Collected ${contracts.length} contracts from local filesystem`);
  return contracts;
}

/**
 * Extract contract name from source code
 */
function extractContractName(sourceCode: string): string | null {
  // Match: contract ContractName
  const match = sourceCode.match(/contract\s+(\w+)/);
  return match ? match[1] : null;
}
