/**
 * Jest test setup
 */

import { ensureDir } from '../src/utils/file-utils';
import path from 'path';

// Increase timeout for integration tests
jest.setTimeout(30000);

// Setup test fixtures directory
beforeAll(async () => {
  const fixturesDir = path.join(__dirname, 'fixtures');
  await ensureDir(fixturesDir);
  await ensureDir(path.join(fixturesDir, 'test-contracts'));
  await ensureDir(path.join(fixturesDir, 'test-sources'));
  await ensureDir(path.join(fixturesDir, 'test-pocs'));
});

// Suppress console output during tests
const originalConsoleLog = console.log;
const originalConsoleError = console.error;

beforeEach(() => {
  console.log = jest.fn();
  console.error = jest.fn();
});

afterEach(() => {
  console.log = originalConsoleLog;
  console.error = originalConsoleError;
});
