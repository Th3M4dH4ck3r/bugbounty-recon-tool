/**
 * Unit tests for static analyzers
 */

import { runStaticRules } from '../../src/analyzers/static-rules';
import { writeFile, ensureDir } from '../../src/utils/file-utils';
import path from 'path';
import fs from 'fs-extra';

describe('Static Analysis', () => {
  const testDir = path.join(__dirname, '../fixtures/test-contracts');

  beforeAll(async () => {
    await ensureDir(testDir);
  });

  afterAll(async () => {
    await fs.remove(testDir);
  });

  describe('Reentrancy Detection', () => {
    it('should detect reentrancy vulnerability', async () => {
      const vulnerableCode = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract Vulnerable {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
`;

      const filePath = path.join(testDir, 'reentrancy.sol');
      await writeFile(filePath, vulnerableCode);

      const findings = await runStaticRules([filePath]);

      expect(findings.length).toBeGreaterThan(0);
      expect(findings.some(f => f.rule_id === 'SC-REENT-01')).toBe(true);
    });

    it('should not flag safe code', async () => {
      const safeCode = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Safe {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
`;

      const filePath = path.join(testDir, 'safe.sol');
      await writeFile(filePath, safeCode);

      const findings = await runStaticRules([filePath]);

      const reentrancyFindings = findings.filter(f => f.rule_id === 'SC-REENT-01');
      expect(reentrancyFindings.length).toBe(0);
    });
  });

  describe('Access Control Detection', () => {
    it('should detect missing access control', async () => {
      const vulnerableCode = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract Vulnerable {
    function emergencyWithdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}
`;

      const filePath = path.join(testDir, 'access-control.sol');
      await writeFile(filePath, vulnerableCode);

      const findings = await runStaticRules([filePath]);

      expect(findings.some(f => f.rule_id === 'SC-ACCESS-01')).toBe(true);
    });
  });

  describe('tx.origin Detection', () => {
    it('should detect tx.origin usage', async () => {
      const vulnerableCode = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract Vulnerable {
    address public owner;

    function setOwner(address newOwner) public {
        require(tx.origin == owner);
        owner = newOwner;
    }
}
`;

      const filePath = path.join(testDir, 'tx-origin.sol');
      await writeFile(filePath, vulnerableCode);

      const findings = await runStaticRules([filePath]);

      expect(findings.some(f => f.rule_id === 'SC-TXORIGIN-01')).toBe(true);
    });
  });

  describe('Integer Overflow Detection', () => {
    it('should detect potential integer overflow in old Solidity', async () => {
      const vulnerableCode = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract Vulnerable {
    mapping(address => uint256) public balances;

    function addInterest(uint256 rate) public {
        balances[msg.sender] = balances[msg.sender] * rate;
    }
}
`;

      const filePath = path.join(testDir, 'overflow.sol');
      await writeFile(filePath, vulnerableCode);

      const findings = await runStaticRules([filePath]);

      expect(findings.some(f => f.rule_id === 'SC-OVERFLOW-01')).toBe(true);
    });
  });
});
