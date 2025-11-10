/**
 * Source code collectors - fetch contracts from various sources
 */

import { logger } from '../utils/logger';
import { collectFromLocal } from './local';
import { collectFromEtherscan } from './etherscan';
import { collectFromGithub } from './github';
import { ContractInfo } from '../types';

export interface CollectorOptions {
  target: string;
  output: string;
  network?: string;
  apiKey?: string;
}

export interface CollectionResult {
  contracts: ContractInfo[];
  source: string;
  timestamp: string;
}

/**
 * Main entry point for collecting contract sources
 */
export async function collectSources(options: CollectorOptions): Promise<CollectionResult> {
  const { target } = options;

  logger.info(`Collecting from target: ${target}`);

  let contracts: ContractInfo[] = [];
  let source = 'unknown';

  // Determine collector based on target format
  if (target.startsWith('etherscan:')) {
    const address = target.replace('etherscan:', '');
    contracts = await collectFromEtherscan(address, options);
    source = 'etherscan';
  } else if (target.startsWith('github:')) {
    const repo = target.replace('github:', '');
    contracts = await collectFromGithub(repo, options);
    source = 'github';
  } else {
    // Default to local filesystem
    contracts = await collectFromLocal(target, options);
    source = 'local';
  }

  return {
    contracts,
    source,
    timestamp: new Date().toISOString(),
  };
}

export * from './local';
export * from './etherscan';
export * from './github';
