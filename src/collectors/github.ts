/**
 * GitHub repository collector
 */

import axios from 'axios';
import path from 'path';
import { logger } from '../utils/logger';
import { writeFile, ensureDir } from '../utils/file-utils';
import { ContractInfo } from '../types';
import { CollectorOptions } from './index';

interface GitHubFile {
  name: string;
  path: string;
  download_url: string;
  type: 'file' | 'dir';
}

/**
 * Collect contracts from GitHub repository
 */
export async function collectFromGithub(
  repo: string,
  options: CollectorOptions
): Promise<ContractInfo[]> {
  const githubToken = options.apiKey || process.env.GITHUB_TOKEN;

  logger.info(`Collecting from GitHub: ${repo}`);

  try {
    const [owner, repoName] = repo.split('/');

    if (!owner || !repoName) {
      throw new Error('Invalid GitHub repository format. Use: owner/repo');
    }

    // Search for Solidity files in the repository
    const files = await findSolidityFilesInRepo(owner, repoName, githubToken);

    if (files.length === 0) {
      logger.warn('No Solidity files found in repository');
      return [];
    }

    const contracts: ContractInfo[] = [];

    // Download each file
    for (const file of files) {
      try {
        const content = await downloadFile(file.download_url, githubToken);
        const contractName = extractContractName(content) || path.basename(file.name, '.sol');

        const contract: ContractInfo = {
          name: contractName,
          path: file.path,
          source_code: content,
        };

        contracts.push(contract);

        // Save to output directory
        if (options.output) {
          await ensureDir(options.output);
          const destPath = path.join(options.output, file.name);
          await writeFile(destPath, content);
          logger.debug(`Saved ${file.name}`);
        }

      } catch (error: any) {
        logger.error(`Failed to download ${file.path}:`, error.message);
      }
    }

    logger.info(`Collected ${contracts.length} contracts from GitHub`);
    return contracts;

  } catch (error: any) {
    logger.error('GitHub collection failed:', error.message);
    throw error;
  }
}

/**
 * Find all Solidity files in a GitHub repository
 */
async function findSolidityFilesInRepo(
  owner: string,
  repo: string,
  token?: string
): Promise<GitHubFile[]> {
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github.v3+json',
  };

  if (token) {
    headers['Authorization'] = `token ${token}`;
  }

  // Use GitHub Search API to find .sol files
  const searchUrl = `https://api.github.com/search/code?q=extension:sol+repo:${owner}/${repo}`;

  try {
    const response = await axios.get(searchUrl, { headers });

    if (response.data.items) {
      return response.data.items.map((item: any) => ({
        name: item.name,
        path: item.path,
        download_url: `https://raw.githubusercontent.com/${owner}/${repo}/main/${item.path}`,
        type: 'file',
      }));
    }

    return [];

  } catch (error: any) {
    if (error.response?.status === 403) {
      throw new Error('GitHub API rate limit exceeded. Provide GITHUB_TOKEN to increase limit.');
    }
    throw error;
  }
}

/**
 * Download file content from GitHub
 */
async function downloadFile(url: string, token?: string): Promise<string> {
  const headers: Record<string, string> = {};

  if (token) {
    headers['Authorization'] = `token ${token}`;
  }

  const response = await axios.get(url, { headers });
  return response.data;
}

/**
 * Extract contract name from source code
 */
function extractContractName(sourceCode: string): string | null {
  const match = sourceCode.match(/contract\s+(\w+)/);
  return match ? match[1] : null;
}
