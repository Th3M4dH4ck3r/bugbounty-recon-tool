/**
 * Etherscan API collector - fetch verified contract source code
 */

import axios from 'axios';
import path from 'path';
import { logger } from '../utils/logger';
import { writeFile, ensureDir } from '../utils/file-utils';
import { ContractInfo } from '../types';
import { CollectorOptions } from './index';

interface EtherscanResponse {
  status: string;
  message: string;
  result: Array<{
    SourceCode: string;
    ABI: string;
    ContractName: string;
    CompilerVersion: string;
    OptimizationUsed: string;
    Runs: string;
    ConstructorArguments: string;
    EVMVersion: string;
    Library: string;
    LicenseType: string;
    Proxy: string;
    Implementation: string;
    SwarmSource: string;
  }>;
}

/**
 * Network configurations for different Etherscan-compatible APIs
 */
const NETWORKS: Record<string, { apiUrl: string; apiKeyEnv: string }> = {
  mainnet: {
    apiUrl: 'https://api.etherscan.io/api',
    apiKeyEnv: 'ETHERSCAN_API_KEY',
  },
  polygon: {
    apiUrl: 'https://api.polygonscan.com/api',
    apiKeyEnv: 'POLYGONSCAN_API_KEY',
  },
  bsc: {
    apiUrl: 'https://api.bscscan.com/api',
    apiKeyEnv: 'BSCSCAN_API_KEY',
  },
  arbitrum: {
    apiUrl: 'https://api.arbiscan.io/api',
    apiKeyEnv: 'ARBISCAN_API_KEY',
  },
  optimism: {
    apiUrl: 'https://api-optimistic.etherscan.io/api',
    apiKeyEnv: 'OPTIMISTIC_ETHERSCAN_API_KEY',
  },
};

/**
 * Collect contract source from Etherscan
 */
export async function collectFromEtherscan(
  address: string,
  options: CollectorOptions
): Promise<ContractInfo[]> {
  const network = options.network || 'mainnet';
  const networkConfig = NETWORKS[network];

  if (!networkConfig) {
    throw new Error(`Unsupported network: ${network}. Supported: ${Object.keys(NETWORKS).join(', ')}`);
  }

  const apiKey = options.apiKey || process.env[networkConfig.apiKeyEnv];

  if (!apiKey) {
    throw new Error(`API key not found for ${network}. Set ${networkConfig.apiKeyEnv} environment variable.`);
  }

  logger.info(`Fetching contract from ${network} Etherscan: ${address}`);

  try {
    // Fetch contract source
    const response = await axios.get<EtherscanResponse>(networkConfig.apiUrl, {
      params: {
        module: 'contract',
        action: 'getsourcecode',
        address,
        apikey: apiKey,
      },
      timeout: 30000,
    });

    if (response.data.status !== '1') {
      throw new Error(`Etherscan API error: ${response.data.message}`);
    }

    const contractData = response.data.result[0];

    if (!contractData || contractData.SourceCode === '') {
      throw new Error(`Contract not verified on ${network} Etherscan`);
    }

    // Parse source code (may be single file or JSON for multiple files)
    const contracts = await parseEtherscanSource(contractData, address, network);

    // Save to output directory
    if (options.output) {
      await ensureDir(options.output);

      for (const contract of contracts) {
        const fileName = `${contract.name}.sol`;
        const filePath = path.join(options.output, fileName);
        await writeFile(filePath, contract.source_code || '');
        contract.path = filePath;
        logger.debug(`Saved ${fileName}`);
      }

      // Save ABI
      const abiPath = path.join(options.output, `${contractData.ContractName}-abi.json`);
      await writeFile(abiPath, contractData.ABI);
      logger.debug(`Saved ABI to ${abiPath}`);
    }

    logger.info(`Successfully fetched ${contracts.length} contract(s) from Etherscan`);
    return contracts;

  } catch (error: any) {
    if (error.response) {
      logger.error(`Etherscan API error: ${error.response.status} - ${error.response.statusText}`);
    } else if (error.request) {
      logger.error('No response from Etherscan API');
    } else {
      logger.error(`Error: ${error.message}`);
    }
    throw error;
  }
}

/**
 * Parse Etherscan source code response
 * Can be either a single string or JSON with multiple files
 */
async function parseEtherscanSource(
  contractData: any,
  address: string,
  network: string
): Promise<ContractInfo[]> {
  const contracts: ContractInfo[] = [];
  let sourceCode = contractData.SourceCode;

  // Check if it's a JSON response (multiple files)
  if (sourceCode.startsWith('{{')) {
    // Remove outer braces and parse
    sourceCode = sourceCode.slice(1, -1);
    const parsed = JSON.parse(sourceCode);

    // Handle both formats: { sources: {...} } or direct file mapping
    const sources = parsed.sources || parsed;

    for (const [fileName, fileData] of Object.entries(sources)) {
      const content = typeof fileData === 'string' ? fileData : (fileData as any).content;

      contracts.push({
        name: extractContractName(fileName, content),
        path: fileName,
        address,
        network,
        compiler_version: contractData.CompilerVersion,
        source_code: content,
        abi: JSON.parse(contractData.ABI),
      });
    }
  } else if (sourceCode.startsWith('{')) {
    // Try parsing as JSON
    try {
      const parsed = JSON.parse(sourceCode);
      const sources = parsed.sources || {};

      for (const [fileName, fileData] of Object.entries(sources)) {
        const content = (fileData as any).content;

        contracts.push({
          name: extractContractName(fileName, content),
          path: fileName,
          address,
          network,
          compiler_version: contractData.CompilerVersion,
          source_code: content,
          abi: JSON.parse(contractData.ABI),
        });
      }
    } catch {
      // Fall back to single file
      contracts.push(createSingleContract(contractData, address, network));
    }
  } else {
    // Single file
    contracts.push(createSingleContract(contractData, address, network));
  }

  return contracts;
}

/**
 * Create a single contract info object
 */
function createSingleContract(contractData: any, address: string, network: string): ContractInfo {
  return {
    name: contractData.ContractName,
    path: `${contractData.ContractName}.sol`,
    address,
    network,
    compiler_version: contractData.CompilerVersion,
    source_code: contractData.SourceCode,
    abi: JSON.parse(contractData.ABI),
  };
}

/**
 * Extract contract name from file path or content
 */
function extractContractName(fileName: string, content: string): string {
  // Try to get from filename first
  const fileMatch = fileName.match(/\/([^\/]+)\.sol$/);
  if (fileMatch) {
    return fileMatch[1];
  }

  // Extract from contract definition
  const contractMatch = content.match(/contract\s+(\w+)/);
  return contractMatch ? contractMatch[1] : path.basename(fileName, '.sol');
}
