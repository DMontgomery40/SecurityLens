// Central index for all security vulnerability patterns
// This file merges all category-specific pattern files into unified exports

import { patternCategories } from './categories.js';
import { injectionPatterns } from './injection.js';
import { cryptographyPatterns } from './cryptography.js';
import { authenticationPatterns } from './authentication.js';
import { ssrfPatterns } from './ssrf.js';
import { sessionPatterns } from './sessions.js';
import { deserializationPatterns } from './deserialization.js';
import { apiPatterns } from './api.js';
import { supplyChainPatterns } from './supply-chain.js';
import { loggingPatterns } from './logging.js';
import { designPatterns } from './design.js';
import { recommendations } from './recommendations.js';

// Merge all pattern categories into a single patterns object
export const patterns = {
  ...injectionPatterns,
  ...cryptographyPatterns,
  ...authenticationPatterns,
  ...ssrfPatterns,
  ...sessionPatterns,
  ...deserializationPatterns,
  ...apiPatterns,
  ...supplyChainPatterns,
  ...loggingPatterns,
  ...designPatterns
};

// Export pattern categories
export { patternCategories };

// Export recommendations
export { recommendations };

// Category metadata for organization and filtering
export const categoryMetadata = {
  injection: {
    name: 'Injection Vulnerabilities',
    description: 'A03:2021 - SQL, Command, XSS, NoSQL, XXE, and Path Traversal attacks',
    patterns: Object.keys(injectionPatterns),
    owasp: 'A03:2021'
  },
  cryptography: {
    name: 'Cryptographic Failures',
    description: 'A02:2021 - Weak encryption, insecure transmission, and exposed secrets',
    patterns: Object.keys(cryptographyPatterns),
    owasp: 'A02:2021'
  },
  authentication: {
    name: 'Authentication & Authorization',
    description: 'A01:2021 & A07:2021 - Broken access control and authentication failures',
    patterns: Object.keys(authenticationPatterns),
    owasp: 'A01:2021, A07:2021'
  },
  ssrf: {
    name: 'Server-Side Request Forgery',
    description: 'A10:2021 - SSRF vulnerabilities',
    patterns: Object.keys(ssrfPatterns),
    owasp: 'A10:2021'
  },
  sessions: {
    name: 'Session Management',
    description: 'Session fixation and related vulnerabilities',
    patterns: Object.keys(sessionPatterns),
    owasp: 'Session Security'
  },
  deserialization: {
    name: 'Insecure Deserialization',
    description: 'A08:2021 - Software and Data Integrity Failures',
    patterns: Object.keys(deserializationPatterns),
    owasp: 'A08:2021'
  },
  api: {
    name: 'API Security',
    description: 'Missing authorization and redirect vulnerabilities',
    patterns: Object.keys(apiPatterns),
    owasp: 'API Security'
  },
  supplyChain: {
    name: 'Supply Chain Security',
    description: 'A06:2021 - Vulnerable and Outdated Components',
    patterns: Object.keys(supplyChainPatterns),
    owasp: 'A06:2021'
  },
  logging: {
    name: 'Logging & Monitoring',
    description: 'A09:2021 - Security Logging and Monitoring Failures',
    patterns: Object.keys(loggingPatterns),
    owasp: 'A09:2021'
  },
  design: {
    name: 'Insecure Design',
    description: 'A04:2021 - Design flaws and business logic vulnerabilities',
    patterns: Object.keys(designPatterns),
    owasp: 'A04:2021'
  }
};

// Default export maintains backward compatibility
export default patterns;