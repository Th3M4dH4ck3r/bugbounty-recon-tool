/**
 * Unit tests for PoC generator
 */

import { generatePoc } from '../../src/poc';
import { Finding } from '../../src/types';
import { readFile, ensureDir } from '../../src/utils/file-utils';
import path from 'path';
import fs from 'fs-extra';

describe('PoC Generator', () => {
  const testOutputDir = path.join(__dirname, '../fixtures/test-pocs');

  beforeAll(async () => {
    await ensureDir(testOutputDir);
  });

  afterAll(async () => {
    await fs.remove(testOutputDir);
  });

  const mockFinding: Finding = {
    id: 'test-finding-1',
    contract: 'SimpleBank',
    source: 'static',
    rule_id: 'SC-REENT-01',
    title: 'Reentrancy in withdraw()',
    severity: 'high',
    impact: 'Funds can be drained',
    likelihood: 'high',
    confidence: 'high',
    recommendation: 'Use checks-effects-interactions pattern',
    description: 'The withdraw function is vulnerable to reentrancy attacks',
    files: [{
      path: 'contracts/SimpleBank.sol',
      line_start: 10,
      line_end: 20,
    }],
    evidence: [],
    tags: ['reentrancy'],
  };

  describe('Hardhat PoC Generation', () => {
    it('should generate Hardhat PoC script', async () => {
      const poc = await generatePoc(mockFinding, {
        outputDir: testOutputDir,
        type: 'hardhat-script',
      });

      expect(poc).toBeDefined();
      expect(poc.type).toBe('hardhat-script');
      expect(poc.path).toContain(testOutputDir);
      expect(poc.simulated).toBe(true);

      // Verify file was created
      const content = await readFile(poc.path);
      expect(content).toContain('SAFETY NOTICE');
      expect(content).toContain('SC-REENT-01');
      expect(content).toContain('reentrancy');
    });

    it('should include safety warnings', async () => {
      const poc = await generatePoc(mockFinding, {
        outputDir: testOutputDir,
        type: 'hardhat-script',
      });

      const content = await readFile(poc.path);
      expect(content).toContain('SIMULATED');
      expect(content).toContain('NO funds');
    });

    it('should generate test case', async () => {
      const poc = await generatePoc(mockFinding, {
        outputDir: testOutputDir,
        type: 'hardhat-script',
      });

      const content = await readFile(poc.path);
      expect(content).toContain('describe');
      expect(content).toContain('it(');
      expect(content).toContain('beforeEach');
    });
  });

  describe('Foundry PoC Generation', () => {
    it('should generate Foundry test', async () => {
      const poc = await generatePoc(mockFinding, {
        outputDir: testOutputDir,
        type: 'foundry-test',
      });

      expect(poc.type).toBe('foundry-test');
      expect(poc.path).toMatch(/\.sol$/);

      const content = await readFile(poc.path);
      expect(content).toContain('pragma solidity');
      expect(content).toContain('import "forge-std/Test.sol"');
      expect(content).toContain('contract');
    });
  });

  describe('PoC Content Validation', () => {
    it('should include finding details', async () => {
      const poc = await generatePoc(mockFinding, {
        outputDir: testOutputDir,
        type: 'hardhat-script',
      });

      const content = await readFile(poc.path);
      expect(content).toContain(mockFinding.title);
      expect(content).toContain(mockFinding.rule_id);
      expect(content).toContain(mockFinding.severity.toUpperCase());
      expect(content).toContain(mockFinding.recommendation);
    });

    it('should extract steps from PoC', async () => {
      const poc = await generatePoc(mockFinding, {
        outputDir: testOutputDir,
        type: 'hardhat-script',
      });

      expect(poc.steps).toBeDefined();
      expect(Array.isArray(poc.steps)).toBe(true);
    });
  });
});
