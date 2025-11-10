#!/usr/bin/env node

/**
 * Scout CLI - Main entry point for the smart contract security scanner
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import dotenv from 'dotenv';
import path from 'path';
import { log } from './utils/logger';
import { collectSources } from './collectors';
import { runStaticAnalysis } from './analyzers';
import { generatePoc } from './poc';
import { generateReport } from './report';
import { startServer } from './server';
import { readJson, writeJson, findSolidityFiles } from './utils/file-utils';
import { Finding, ScanConfig } from './types';
import { v4 as uuidv4 } from 'uuid';

// Load environment variables
dotenv.config();

const program = new Command();

program
  .name('scout')
  .description('Swiss-Army-Knife tool for smart contract bug bounties')
  .version('1.0.0');

/**
 * scout collect - Collect contract sources
 */
program
  .command('collect')
  .description('Collect contract sources from various locations')
  .option('-t, --target <source>', 'Target source (local path, etherscan:0x..., github:owner/repo)', 'contracts')
  .option('-o, --output <dir>', 'Output directory', './sources')
  .option('-n, --network <network>', 'Network for address collection (mainnet, polygon, etc.)', 'mainnet')
  .option('--api-key <key>', 'API key for external services')
  .action(async (options) => {
    const spinner = ora('Collecting contract sources...').start();

    try {
      const result = await collectSources({
        target: options.target,
        output: options.output,
        network: options.network,
        apiKey: options.apiKey || process.env.ETHERSCAN_API_KEY,
      });

      spinner.succeed(chalk.green(`Collected ${result.contracts.length} contract(s)`));

      result.contracts.forEach((contract: any) => {
        log.info(`  → ${contract.name} (${contract.path})`);
      });

      await writeJson(path.join(options.output, 'collection-manifest.json'), result);

    } catch (error: any) {
      spinner.fail(chalk.red('Collection failed'));
      log.error(error.message);
      process.exit(1);
    }
  });

/**
 * scout analyze - Run static analysis
 */
program
  .command('analyze')
  .description('Run static analysis on contracts')
  .argument('[type]', 'Analysis type (static, bytecode, graph)', 'static')
  .option('-s, --source <path>', 'Source directory or file', './contracts')
  .option('-o, --output <file>', 'Output file for findings', './reports/findings.json')
  .option('-r, --rules <file>', 'Custom rules file')
  .option('--slither', 'Enable Slither integration', false)
  .option('--mythx', 'Enable MythX integration', false)
  .option('--format <format>', 'Output format (json, markdown)', 'json')
  .action(async (type, options) => {
    const spinner = ora(`Running ${type} analysis...`).start();

    try {
      // Find all Solidity files
      const files = await findSolidityFiles(options.source);

      if (files.length === 0) {
        spinner.warn(chalk.yellow('No Solidity files found'));
        return;
      }

      spinner.text = `Analyzing ${files.length} contract(s)...`;

      // Run analysis
      const findings = await runStaticAnalysis({
        files,
        rules: options.rules,
        enableSlither: options.slither,
        enableMythx: options.mythx,
      });

      spinner.succeed(chalk.green(`Analysis complete: ${findings.length} finding(s)`));

      // Display findings summary
      const severityCounts: Record<string, number> = {};
      findings.forEach((finding: Finding) => {
        severityCounts[finding.severity] = (severityCounts[finding.severity] || 0) + 1;
        log.finding(finding.severity, `${finding.title} (${finding.rule_id})`);
      });

      console.log('\n' + chalk.bold('Summary:'));
      Object.entries(severityCounts).forEach(([severity, count]) => {
        const color = {
          critical: chalk.bgRed.white,
          high: chalk.red,
          medium: chalk.yellow,
          low: chalk.blue,
          informational: chalk.gray,
        }[severity] || chalk.white;
        console.log(`  ${color(severity.padEnd(15))} ${count}`);
      });

      // Save findings
      await writeJson(options.output, findings);
      log.success(`Findings saved to ${options.output}`);

    } catch (error: any) {
      spinner.fail(chalk.red('Analysis failed'));
      log.error(error.message);
      if (error.stack) log.debug(error.stack);
      process.exit(1);
    }
  });

/**
 * scout simulate - Simulate transactions on a fork
 */
program
  .command('simulate')
  .description('Simulate transactions on a forked network')
  .option('--fork-url <url>', 'Fork RPC URL', process.env.LOCAL_RPC_URL || 'http://localhost:8545')
  .option('-c, --contract <address>', 'Contract address to simulate')
  .option('-f, --function <name>', 'Function name to call')
  .option('-a, --args <args>', 'Function arguments (JSON array)')
  .option('--block <number>', 'Fork from specific block number')
  .action(async (options) => {
    const spinner = ora('Setting up fork and simulating...').start();

    try {
      log.warn('Simulation feature requires Hardhat/Foundry Anvil running');
      log.info(`Fork URL: ${options.forkUrl}`);

      if (options.contract) {
        log.info(`Contract: ${options.contract}`);
      }

      spinner.info(chalk.yellow('Simulation stub - See dynamic/fork-manager.ts for implementation'));

    } catch (error: any) {
      spinner.fail(chalk.red('Simulation failed'));
      log.error(error.message);
      process.exit(1);
    }
  });

/**
 * scout fuzz - Run fuzzing tests
 */
program
  .command('fuzz')
  .description('Run fuzzing tests on contracts')
  .option('-s, --source <path>', 'Source directory', './contracts')
  .option('-c, --contract <name>', 'Contract name to fuzz')
  .option('--iterations <n>', 'Number of iterations', '1000')
  .option('--echidna', 'Use Echidna fuzzer', false)
  .action(async (options) => {
    const spinner = ora('Running fuzzer...').start();

    try {
      log.warn('Fuzzing requires Echidna or custom fuzzer - see symbolic/wrappers.ts');
      spinner.info(chalk.yellow('Fuzzing stub - Integration in progress'));

    } catch (error: any) {
      spinner.fail(chalk.red('Fuzzing failed'));
      log.error(error.message);
      process.exit(1);
    }
  });

/**
 * scout poc - Generate Proof of Concept
 */
program
  .command('poc')
  .description('Generate exploit PoC from findings')
  .option('-f, --finding <id>', 'Finding ID to generate PoC for')
  .option('-i, --input <file>', 'Findings JSON file', './reports/findings.json')
  .option('-o, --output <dir>', 'Output directory for PoCs', './pocs')
  .option('-t, --type <type>', 'PoC type (hardhat, foundry, brownie)', 'hardhat')
  .action(async (options) => {
    const spinner = ora('Generating PoC...').start();

    try {
      // Load findings
      const findings: Finding[] = await readJson(options.input);

      let targetFindings = findings;
      if (options.finding) {
        targetFindings = findings.filter(f => f.id === options.finding);
        if (targetFindings.length === 0) {
          spinner.fail(chalk.red(`Finding ${options.finding} not found`));
          return;
        }
      }

      spinner.text = `Generating PoCs for ${targetFindings.length} finding(s)...`;

      for (const finding of targetFindings) {
        const poc = await generatePoc(finding, {
          outputDir: options.output,
          type: options.type,
        });

        log.success(`Generated PoC: ${poc.path}`);

        // Update finding with PoC info
        finding.poc = poc;
      }

      // Save updated findings
      await writeJson(options.input, findings);
      spinner.succeed(chalk.green(`Generated ${targetFindings.length} PoC(s)`));

    } catch (error: any) {
      spinner.fail(chalk.red('PoC generation failed'));
      log.error(error.message);
      if (error.stack) log.debug(error.stack);
      process.exit(1);
    }
  });

/**
 * scout report - Generate reports
 */
program
  .command('report')
  .description('Generate security reports from findings')
  .option('-i, --input <file>', 'Findings JSON file', './reports/findings.json')
  .option('-o, --output <file>', 'Output file', './reports/report.md')
  .option('-f, --format <format>', 'Output format (markdown, html, pdf, json)', 'markdown')
  .option('--template <file>', 'Custom report template')
  .action(async (options) => {
    const spinner = ora('Generating report...').start();

    try {
      const findings: Finding[] = await readJson(options.input);

      if (findings.length === 0) {
        spinner.warn(chalk.yellow('No findings to report'));
        return;
      }

      const report = await generateReport(findings, {
        format: options.format,
        outputPath: options.output,
        template: options.template,
      });

      spinner.succeed(chalk.green(`Report generated: ${report.path}`));
      log.info(`Format: ${report.format}`);
      log.info(`Findings: ${findings.length}`);

    } catch (error: any) {
      spinner.fail(chalk.red('Report generation failed'));
      log.error(error.message);
      if (error.stack) log.debug(error.stack);
      process.exit(1);
    }
  });

/**
 * scout server - Start API server
 */
program
  .command('server')
  .description('Start the Scout API server and dashboard')
  .option('-p, --port <port>', 'Server port', process.env.API_PORT || '3000')
  .option('-h, --host <host>', 'Server host', process.env.API_HOST || '0.0.0.0')
  .action(async (options) => {
    try {
      log.info(chalk.bold('Starting Scout API Server...'));
      log.info(`Host: ${options.host}`);
      log.info(`Port: ${options.port}`);

      await startServer({
        port: parseInt(options.port),
        host: options.host,
      });

    } catch (error: any) {
      log.error('Failed to start server');
      log.error(error.message);
      process.exit(1);
    }
  });

/**
 * scout scan - Run full scan workflow
 */
program
  .command('scan')
  .description('Run complete security scan (collect + analyze + poc + report)')
  .option('-t, --target <source>', 'Target source', 'contracts')
  .option('-o, --output <dir>', 'Output directory', './reports')
  .option('--rpc <url>', 'RPC URL for dynamic analysis')
  .option('--network <network>', 'Network name', 'mainnet')
  .option('--skip-poc', 'Skip PoC generation', false)
  .action(async (options) => {
    const runId = uuidv4().slice(0, 8);
    log.info(chalk.bold(`\n🔍 Starting security scan [${runId}]\n`));

    const spinner = ora();

    try {
      // Step 1: Collect
      spinner.start('Step 1/4: Collecting sources...');
      const collection = await collectSources({
        target: options.target,
        output: path.join(options.output, 'sources'),
        network: options.network,
      });
      spinner.succeed(`Collected ${collection.contracts.length} contract(s)`);

      // Step 2: Analyze
      spinner.start('Step 2/4: Running security analysis...');
      const files = await findSolidityFiles(options.target);
      const findings = await runStaticAnalysis({ files });
      spinner.succeed(`Found ${findings.length} potential issue(s)`);

      // Step 3: Generate PoCs (optional)
      if (!options.skipPoc && findings.length > 0) {
        spinner.start('Step 3/4: Generating PoCs...');
        for (const finding of findings.filter(f => ['critical', 'high'].includes(f.severity))) {
          const poc = await generatePoc(finding, {
            outputDir: path.join(options.output, 'pocs'),
            type: 'hardhat-script',
          });
          finding.poc = poc;
        }
        spinner.succeed('PoCs generated for critical/high findings');
      } else {
        spinner.info('Step 3/4: Skipping PoC generation');
      }

      // Step 4: Generate report
      spinner.start('Step 4/4: Generating report...');
      const reportPath = path.join(options.output, `report-${runId}.md`);
      await generateReport(findings, {
        format: 'markdown',
        outputPath: reportPath,
      });
      spinner.succeed(`Report generated: ${reportPath}`);

      // Summary
      console.log(chalk.bold('\n✨ Scan Complete!\n'));
      console.log(chalk.gray('─'.repeat(50)));
      console.log(`${chalk.bold('Findings:')} ${findings.length}`);
      console.log(`${chalk.bold('Report:')} ${reportPath}`);
      console.log(chalk.gray('─'.repeat(50)) + '\n');

    } catch (error: any) {
      spinner.fail('Scan failed');
      log.error(error.message);
      if (error.stack) log.debug(error.stack);
      process.exit(1);
    }
  });

// Parse command line arguments
program.parse(process.argv);

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
