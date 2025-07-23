// Logging and Monitoring patterns
// A09:2021 - Security Logging and Monitoring Failures

import { patternCategories } from './categories.js';

export const loggingPatterns = {
  insufficientLogging: {
    // Basic console logging statements
    pattern: /(?<!logger\.)\b(?:print|console\.log)\b\s*\(/i,
    description: 'Inadequate logging practices',
    severity: 'LOW',
    category: patternCategories.LOGGING_FAILURES,
    subcategory: '778',
    cwe: '778'
  },

  securityLogging: {
    pattern: /console\.log|print|logger\.(?:info|error|warn)/i,
    description: 'Potentially insufficient or insecure logging',
    severity: 'LOW',
    category: patternCategories.LOGGING_FAILURES,
    subcategory: '778',
    cwe: '778'
  }
};

export default loggingPatterns;