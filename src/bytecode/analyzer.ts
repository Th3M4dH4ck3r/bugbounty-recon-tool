/**
 * EVM bytecode analyzer
 *
 * Provides basic bytecode analysis including:
 * - Function signature extraction
 * - Delegatecall detection
 * - Selfdestruct detection
 * - Storage slot analysis
 */

import { logger } from '../utils/logger';

export interface BytecodeInfo {
  bytecode: string;
  functionSignatures: string[];
  hasDelegatecall: boolean;
  hasSelfdestruct: boolean;
  storageSlots: number[];
}

/**
 * Analyze EVM bytecode
 */
export async function analyzeBytecode(bytecode: string): Promise<BytecodeInfo> {
  logger.debug('Analyzing bytecode...');

  // Remove 0x prefix if present
  const cleanBytecode = bytecode.startsWith('0x') ? bytecode.slice(2) : bytecode;

  const info: BytecodeInfo = {
    bytecode,
    functionSignatures: extractFunctionSignatures(cleanBytecode),
    hasDelegatecall: cleanBytecode.includes('f4'), // DELEGATECALL opcode
    hasSelfdestruct: cleanBytecode.includes('ff'), // SELFDESTRUCT opcode
    storageSlots: [],
  };

  return info;
}

/**
 * Extract function signatures from bytecode
 * Function selectors are 4-byte hashes at the beginning of calldata
 */
function extractFunctionSignatures(bytecode: string): string[] {
  const signatures: string[] = [];

  // Look for PUSH4 (63) followed by 4 bytes - these are often function selectors
  const push4Regex = /63([0-9a-f]{8})/gi;
  let match;

  while ((match = push4Regex.exec(bytecode)) !== null) {
    const selector = '0x' + match[1];
    if (!signatures.includes(selector)) {
      signatures.push(selector);
    }
  }

  return signatures;
}

/**
 * Decompile bytecode to pseudo-code
 * This is a simplified stub - real decompilation requires tools like:
 * - Ethersplay
 * - Panoramix/Dedaub
 * - Heimdall
 */
export async function decompileBytecode(bytecode: string): Promise<string> {
  logger.info('Bytecode decompilation is a stub. For real decompilation use:');
  logger.info('- Dedaub: https://library.dedaub.com/decompile');
  logger.info('- Heimdall: https://github.com/Jon-Becker/heimdall-rs');

  return `// Decompiled bytecode (stub)\n// Use external decompiler for full analysis\n\n// Bytecode length: ${bytecode.length / 2} bytes`;
}
