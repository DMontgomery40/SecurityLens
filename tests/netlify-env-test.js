#!/usr/bin/env node

// Test script to verify Netlify function environment variable handling
import assert from 'assert';

// Simulate Netlify function environment variable parsing logic
function parseNetlifyConcurrency(envValue, defaultValue = 10) {
  const rawConcurrency = parseInt(envValue) || defaultValue;
  return Math.min(Math.max(rawConcurrency, 1), 50); // Clamp between 1-50
}

console.log('Testing Netlify function concurrency environment variable handling...');

// Test cases for environment variable parsing
const testCases = [
  { env: undefined, expected: 10, description: 'undefined env should use default (10)' },
  { env: null, expected: 10, description: 'null env should use default (10)' },
  { env: '', expected: 10, description: 'empty string should use default (10)' },
  { env: 'invalid', expected: 10, description: 'invalid string should use default (10)' },
  { env: '5', expected: 5, description: 'valid number string should parse correctly' },
  { env: '0', expected: 10, description: 'zero should fall back to default (10) due to falsy check' },
  { env: '-5', expected: 1, description: 'negative number should be clamped to minimum (1)' },
  { env: '25', expected: 25, description: 'normal value should pass through' },
  { env: '50', expected: 50, description: 'maximum value should be allowed' },
  { env: '100', expected: 50, description: 'too high value should be clamped to maximum (50)' },
  { env: '1000', expected: 50, description: 'way too high value should be clamped to maximum (50)' }
];

let passed = 0;
let failed = 0;

for (const testCase of testCases) {
  try {
    const result = parseNetlifyConcurrency(testCase.env);
    assert.strictEqual(result, testCase.expected, 
      `Expected ${testCase.expected}, got ${result} for env value "${testCase.env}"`);
    console.log(`✓ ${testCase.description}`);
    passed++;
  } catch (error) {
    console.log(`✗ ${testCase.description}: ${error.message}`);
    failed++;
  }
}

// Test the actual Netlify function code pattern
console.log('\\nTesting actual Netlify function pattern...');

// Simulate how the environment variable would be used in the Netlify function
function simulateNetlifyFunction(mockEnv) {
  // Save original env
  const originalEnv = process.env.SCANNER_CONCURRENCY;
  
  try {
    // Set mock environment
    if (mockEnv !== undefined) {
      process.env.SCANNER_CONCURRENCY = mockEnv;
    } else {
      delete process.env.SCANNER_CONCURRENCY;
    }
    
    // Simulate the exact code from scan-repository.js
    const rawConcurrency = parseInt(process.env.SCANNER_CONCURRENCY) || 10;
    const concurrency = Math.min(Math.max(rawConcurrency, 1), 50);
    
    return concurrency;
  } finally {
    // Restore original env
    if (originalEnv !== undefined) {
      process.env.SCANNER_CONCURRENCY = originalEnv;
    } else {
      delete process.env.SCANNER_CONCURRENCY;
    }
  }
}

const netlifyTestCases = [
  { env: undefined, expected: 10 },
  { env: '2', expected: 2 },
  { env: '50', expected: 50 },
  { env: '100', expected: 50 },
  { env: '0', expected: 10 }
];

for (const testCase of netlifyTestCases) {
  const result = simulateNetlifyFunction(testCase.env);
  assert.strictEqual(result, testCase.expected, 
    `Netlify function: Expected ${testCase.expected}, got ${result} for env "${testCase.env}"`);
  console.log(`✓ Netlify env "${testCase.env || 'undefined'}" -> concurrency ${result}`);
  passed++;
}

console.log('\\n=== Netlify Environment Test Summary ===');
console.log(`✓ ${passed} tests passed`);
if (failed > 0) {
  console.log(`✗ ${failed} tests failed`);
  process.exit(1);
} else {
  console.log('All Netlify environment variable tests passed! 🎉');
}