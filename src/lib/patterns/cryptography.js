// Cryptographic vulnerability patterns
// A02:2021 - Cryptographic Failures

import { patternCategories } from './categories.js';

export const cryptographyPatterns = {
  weakCrypto: {
    // Weak hash functions such as MD5 or SHA1
    // Regex sourced from Red Canary open detections
    pattern: /crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/i,
    description: 'Use of weak cryptographic hash function',
    severity: 'HIGH',
    category: patternCategories.CRYPTO_FAILURES,
    subcategory: '326',
    cwe: '326'
  },

  insecureCryptoUsage: {
    // Deprecated or insecure crypto primitives
    pattern: /crypto\.(?:createCipher(?:iv)?|createDecipher(?:iv)?)\s*\(/i,
    description: 'Use of deprecated cryptographic functions',
    severity: 'HIGH',
    category: patternCategories.CRYPTO_FAILURES,
    subcategory: '327',
    cwe: '327'
  },

  sensitiveExposure: {
    // Detects plaintext credentials or keys in code
    pattern: /\b(?:apikey|secretkey|password|credentials)\b\s*[:=]\s*['"][^'"\n]{8,}['"]/i,
    description: 'Exposure of sensitive data in code',
    severity: 'HIGH',
    category: patternCategories.CRYPTO_FAILURES,
    subcategory: '200',
    cwe: '200'
  },

  insecureTransmission: {
    // Detects cleartext transmission over HTTP (excluding local networks)
    pattern: /http:\/\/(?!localhost|127\.0\.0\.1|10\.|192\.168|172\.(?:1[6-9]|2\d|3[01]))/i,
    description: 'Potential insecure data transmission',
    severity: 'MEDIUM',
    category: patternCategories.CRYPTO_FAILURES,
    subcategory: '319',
    cwe: '319'
  },

  insecureSubmission: {
    pattern: /fetch\s*\(\s*['"]http:\/\/(?!localhost|127\.0\.0\.1)/i,
    description: 'Insecure form or data submission over HTTP',
    severity: 'HIGH',
    category: patternCategories.CRYPTO_FAILURES,
    subcategory: '319',
    cwe: '319'
  }
};

export default cryptographyPatterns;