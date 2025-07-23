#!/usr/bin/env node

import assert from 'assert';
import { RepositoryCrawler, ScanError } from '../src/lib/RepositoryCrawler.js';

// Test utilities
class TestUtils {
  static createMockCrawler(config = {}) {
    return new RepositoryCrawler({
      concurrency: 2,
      ...config
    });
  }

  static async assertThrows(fn, expectedErrorCode, message) {
    try {
      await fn();
      assert.fail(`Expected function to throw ScanError with code ${expectedErrorCode}, but it didn't throw`);
    } catch (error) {
      if (error instanceof ScanError) {
        assert.strictEqual(error.code, expectedErrorCode, 
          `Expected error code ${expectedErrorCode}, got ${error.code}: ${error.message}`);
      } else {
        assert.fail(`Expected ScanError, got ${error.constructor.name}: ${error.message}`);
      }
    }
  }

  static assertScanError(error, expectedCode, expectedMessage) {
    assert(error instanceof ScanError, 'Expected error to be instance of ScanError');
    assert.strictEqual(error.code, expectedCode, `Expected error code ${expectedCode}, got ${error.code}`);
    assert(error.message.includes(expectedMessage), 
      `Expected error message to include "${expectedMessage}", got "${error.message}"`);
    assert(typeof error.details === 'object', 'Expected error.details to be an object');
  }
}

// Test suite for ScanError class
console.log('Testing ScanError class...');

// Test ScanError constructor
const testError = new ScanError('TEST_CODE', 'Test message', { detail: 'value' });
assert.strictEqual(testError.name, 'ScanError');
assert.strictEqual(testError.code, 'TEST_CODE');
assert.strictEqual(testError.message, 'Test message');
assert.deepStrictEqual(testError.details, { detail: 'value' });
console.log('✓ ScanError constructor works correctly');

// Test ScanError with minimal parameters
const minimalError = new ScanError('MIN_CODE', 'Minimal message');
assert.strictEqual(minimalError.code, 'MIN_CODE');
assert.deepStrictEqual(minimalError.details, {});
console.log('✓ ScanError works with minimal parameters');

// Test suite for RepositoryCrawler error handling
console.log('\\nTesting RepositoryCrawler error handling...');

// Test crawler initialization and error collection
const crawler = TestUtils.createMockCrawler();
assert.strictEqual(crawler.errors.length, 0, 'New crawler should have no errors');
assert.strictEqual(crawler.config.concurrency, 2, 'Concurrency should be set correctly');
console.log('✓ Crawler initialization works correctly');

// Test error collection methods
crawler.addError('TEST_ERROR', 'Test error message', { testDetail: 'value' });
assert.strictEqual(crawler.errors.length, 1, 'Should have one error after adding');
const addedError = crawler.getErrors()[0];
TestUtils.assertScanError(addedError, 'TEST_ERROR', 'Test error message');
assert.strictEqual(addedError.details.testDetail, 'value');
console.log('✓ Error collection methods work correctly');

// Test error clearing
crawler.clearErrors();
assert.strictEqual(crawler.errors.length, 0, 'Errors should be cleared');
console.log('✓ Error clearing works correctly');

// Test URL parsing errors
console.log('\\nTesting URL parsing errors...');

await TestUtils.assertThrows(
  () => crawler.parseGitHubUrl('not-a-github-url'),
  'INVALID_URL'
);
console.log('✓ Invalid URL throws INVALID_URL error');

await TestUtils.assertThrows(
  () => crawler.parseGitHubUrl('https://example.com/repo'),
  'INVALID_URL'
);
console.log('✓ Non-GitHub URL throws INVALID_URL error');

// Test valid URL parsing
const validResult = crawler.parseGitHubUrl('https://github.com/owner/repo');
assert.strictEqual(validResult.owner, 'owner');
assert.strictEqual(validResult.repo, 'repo');
console.log('✓ Valid URL parsing works correctly');

// Test missing token scenario
console.log('\\nTesting authentication errors...');

const noTokenCrawler = new RepositoryCrawler();
await TestUtils.assertThrows(
  () => noTokenCrawler.getFiles(null, 'owner', 'repo'),
  'MISSING_TOKEN'
);
console.log('✓ Missing token throws MISSING_TOKEN error');

// Test invalid token scenario (simulated)
const invalidTokenCrawler = new RepositoryCrawler();
await TestUtils.assertThrows(
  () => invalidTokenCrawler.getFiles('invalid-token', 'owner', 'repo'),
  'AUTH_FAILED'
);
console.log('✓ Invalid token scenario handled correctly');

// Test concurrency configuration
console.log('\\nTesting concurrency configuration...');

const highConcurrencyCrawler = new RepositoryCrawler({ concurrency: 100 });
assert.strictEqual(highConcurrencyCrawler.config.concurrency, 100);
console.log('✓ High concurrency setting works');

const lowConcurrencyCrawler = new RepositoryCrawler({ concurrency: 1 });
assert.strictEqual(lowConcurrencyCrawler.config.concurrency, 1);
console.log('✓ Low concurrency setting works');

// Test semaphore functionality
console.log('\\nTesting semaphore functionality...');

const semaphoreCrawler = new RepositoryCrawler({ concurrency: 2 });
const semaphore = semaphoreCrawler.semaphore;

// Test that semaphore allows up to concurrency limit
let runningTasks = 0;
let maxConcurrentTasks = 0;

const testTask = async (delay) => {
  return semaphore.execute(async () => {
    runningTasks++;
    maxConcurrentTasks = Math.max(maxConcurrentTasks, runningTasks);
    await new Promise(resolve => setTimeout(resolve, delay));
    runningTasks--;
    return 'completed';
  });
};

const promises = [
  testTask(50),
  testTask(50),
  testTask(50),
  testTask(50)
];

await Promise.all(promises);
assert(maxConcurrentTasks <= 2, `Expected max concurrent tasks <= 2, got ${maxConcurrentTasks}`);
console.log('✓ Semaphore correctly limits concurrency');

// Test error propagation through semaphore
const errorTask = async () => {
  return semaphore.execute(async () => {
    throw new Error('Test error');
  });
};

try {
  await errorTask();
  assert.fail('Expected error to be thrown');
} catch (error) {
  assert.strictEqual(error.message, 'Test error');
}
console.log('✓ Semaphore correctly propagates errors');

// Summary
console.log('\\n=== Test Summary ===');
console.log('✓ All error handling tests passed successfully');
console.log('✓ ScanError class works correctly');
console.log('✓ RepositoryCrawler error collection works');
console.log('✓ URL parsing errors handled properly');
console.log('✓ Authentication errors handled properly');
console.log('✓ Concurrency configuration works');
console.log('✓ Semaphore functionality verified');
console.log('\\nAll tests completed successfully! 🎉');