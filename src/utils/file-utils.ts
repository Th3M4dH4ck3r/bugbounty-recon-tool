/**
 * File system utilities
 */

import fs from 'fs-extra';
import path from 'path';
import glob from 'fast-glob';
import { logger } from './logger';

/**
 * Ensure a directory exists, creating it if necessary
 */
export async function ensureDir(dirPath: string): Promise<void> {
  try {
    await fs.ensureDir(dirPath);
  } catch (error) {
    logger.error(`Failed to create directory ${dirPath}:`, error);
    throw error;
  }
}

/**
 * Read a JSON file safely
 */
export async function readJson<T = any>(filePath: string): Promise<T> {
  try {
    return await fs.readJson(filePath);
  } catch (error) {
    logger.error(`Failed to read JSON file ${filePath}:`, error);
    throw error;
  }
}

/**
 * Write data to a JSON file
 */
export async function writeJson(filePath: string, data: any): Promise<void> {
  try {
    await fs.ensureDir(path.dirname(filePath));
    await fs.writeJson(filePath, data, { spaces: 2 });
  } catch (error) {
    logger.error(`Failed to write JSON file ${filePath}:`, error);
    throw error;
  }
}

/**
 * Find Solidity files in a directory
 */
export async function findSolidityFiles(dir: string): Promise<string[]> {
  try {
    const files = await glob('**/*.sol', {
      cwd: dir,
      absolute: true,
      ignore: ['**/node_modules/**', '**/test/**', '**/mock/**'],
    });
    return files;
  } catch (error) {
    logger.error(`Failed to find Solidity files in ${dir}:`, error);
    throw error;
  }
}

/**
 * Read file contents
 */
export async function readFile(filePath: string): Promise<string> {
  try {
    return await fs.readFile(filePath, 'utf-8');
  } catch (error) {
    logger.error(`Failed to read file ${filePath}:`, error);
    throw error;
  }
}

/**
 * Write file contents
 */
export async function writeFile(filePath: string, content: string): Promise<void> {
  try {
    await fs.ensureDir(path.dirname(filePath));
    await fs.writeFile(filePath, content, 'utf-8');
  } catch (error) {
    logger.error(`Failed to write file ${filePath}:`, error);
    throw error;
  }
}

/**
 * Copy a file or directory
 */
export async function copy(src: string, dest: string): Promise<void> {
  try {
    await fs.copy(src, dest);
  } catch (error) {
    logger.error(`Failed to copy ${src} to ${dest}:`, error);
    throw error;
  }
}

/**
 * Check if a file or directory exists
 */
export async function exists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Get file stats
 */
export async function getStats(filePath: string): Promise<fs.Stats> {
  return fs.stat(filePath);
}

/**
 * Create a safe filename from a string
 */
export function sanitizeFilename(name: string): string {
  return name
    .replace(/[^a-z0-9_\-]/gi, '_')
    .toLowerCase();
}

/**
 * Get relative path from base directory
 */
export function getRelativePath(from: string, to: string): string {
  return path.relative(from, to);
}
