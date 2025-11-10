/**
 * End-to-end integration test
 * Tests the complete workflow: collect → analyze → poc → report
 */

import { collectFromLocal } from '../../src/collectors/local';
import { runStaticAnalysis } from '../../src/analyzers';
import { generatePoc } from '../../src/poc';
import { generateReport } from '../../src/report';
import { writeFile, ensureDir, exists } from '../../src/utils/file-utils';
import path from 'path';
import fs from 'fs-extra';

describe('End-to-End Workflow', () => {
  const testDir = path.join(__dirname, '../fixtures/e2e-test');
  const contractsDir = path.join(testDir, 'contracts');
  const outputDir = path.join(testDir, 'output');

  beforeAll(async () => {
    await ensureDir(contractsDir);
    await ensureDir(outputDir);

    // Create a vulnerable contract for testing
    const vulnerableContract = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }

    function emergencyWithdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}
`;

    await writeFile(path.join(contractsDir, 'VulnerableBank.sol'), vulnerableContract);
  });

  afterAll(async () => {
    await fs.remove(testDir);
  });

  it('should complete full security scan workflow', async () => {
    // Step 1: Collect contracts
    console.log('Step 1: Collecting contracts...');
    const contracts = await collectFromLocal(contractsDir, {
      target: contractsDir,
      output: outputDir,
    });

    expect(contracts.length).toBeGreaterThan(0);
    expect(contracts[0].name).toBe('VulnerableBank');

    // Step 2: Run static analysis
    console.log('Step 2: Running static analysis...');
    const contractPaths = contracts.map(c => c.path);
    const findings = await runStaticAnalysis({
      files: contractPaths,
    });

    expect(findings.length).toBeGreaterThan(0);

    // Should detect reentrancy
    const reentrancyFinding = findings.find(f => f.rule_id === 'SC-REENT-01');
    expect(reentrancyFinding).toBeDefined();

    // Should detect missing access control
    const accessControlFinding = findings.find(f => f.rule_id === 'SC-ACCESS-01');
    expect(accessControlFinding).toBeDefined();

    // Step 3: Generate PoC for high-severity findings
    console.log('Step 3: Generating PoCs...');
    const highSeverityFindings = findings.filter(f => f.severity === 'high');

    for (const finding of highSeverityFindings.slice(0, 1)) {
      const poc = await generatePoc(finding, {
        outputDir: path.join(outputDir, 'pocs'),
        type: 'hardhat-script',
      });

      expect(poc).toBeDefined();
      expect(await exists(poc.path)).toBe(true);

      // Update finding with PoC info
      finding.poc = poc;
    }

    // Step 4: Generate report
    console.log('Step 4: Generating report...');
    const reportPath = path.join(outputDir, 'security-report.md');
    const report = await generateReport(findings, {
      format: 'markdown',
      outputPath: reportPath,
    });

    expect(report.findingsCount).toBe(findings.length);
    expect(await exists(reportPath)).toBe(true);

    // Verify report content
    const { readFile } = await import('../../src/utils/file-utils');
    const reportContent = await readFile(reportPath);

    expect(reportContent).toContain('Smart Contract Security Report');
    expect(reportContent).toContain('VulnerableBank');
    expect(reportContent).toContain('SC-REENT-01');
    expect(reportContent).toContain('Severity Distribution');

    console.log('\n✓ End-to-end workflow completed successfully!');
    console.log(`  Contracts analyzed: ${contracts.length}`);
    console.log(`  Findings detected: ${findings.length}`);
    console.log(`  PoCs generated: ${highSeverityFindings.length}`);
    console.log(`  Report saved to: ${reportPath}`);
  });

  it('should handle contracts with no vulnerabilities', async () => {
    const safeContract = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeContract {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }

    function getValue() public view returns (uint256) {
        return value;
    }
}
`;

    const safeContractPath = path.join(contractsDir, 'SafeContract.sol');
    await writeFile(safeContractPath, safeContract);

    const findings = await runStaticAnalysis({
      files: [safeContractPath],
    });

    // Should have minimal or no findings
    const criticalFindings = findings.filter(f => f.severity === 'critical');
    expect(criticalFindings.length).toBe(0);
  });
});
