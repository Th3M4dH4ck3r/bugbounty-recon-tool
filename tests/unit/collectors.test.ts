/**
 * Unit tests for source collectors
 */

import { collectFromLocal } from '../../src/collectors/local';
import { writeFile, ensureDir } from '../../src/utils/file-utils';
import path from 'path';
import fs from 'fs-extra';

describe('Collectors', () => {
  const testDir = path.join(__dirname, '../fixtures/test-sources');

  beforeAll(async () => {
    await ensureDir(testDir);
  });

  afterAll(async () => {
    await fs.remove(testDir);
  });

  describe('Local Collector', () => {
    it('should collect contracts from local filesystem', async () => {
      // Create test contract
      const contractCode = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestContract {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }
}
`;

      await writeFile(path.join(testDir, 'TestContract.sol'), contractCode);

      const contracts = await collectFromLocal(testDir, {
        target: testDir,
        output: testDir,
      });

      expect(contracts.length).toBeGreaterThan(0);
      expect(contracts[0].name).toBe('TestContract');
      expect(contracts[0].source_code).toContain('contract TestContract');
    });

    it('should handle empty directories', async () => {
      const emptyDir = path.join(testDir, 'empty');
      await ensureDir(emptyDir);

      const contracts = await collectFromLocal(emptyDir, {
        target: emptyDir,
        output: emptyDir,
      });

      expect(contracts.length).toBe(0);
    });

    it('should extract contract names', async () => {
      const contractCode = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MyToken {
    string public name = "MyToken";
}
`;

      await writeFile(path.join(testDir, 'MyToken.sol'), contractCode);

      const contracts = await collectFromLocal(testDir, {
        target: testDir,
        output: testDir,
      });

      const myToken = contracts.find(c => c.name === 'MyToken');
      expect(myToken).toBeDefined();
    });
  });
});
