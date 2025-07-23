// Authentication and Authorization vulnerability patterns
// A07:2021 - Auth & Verification Failures
// A01:2021 - Broken Access Control

import { patternCategories } from './categories.js';

export const authenticationPatterns = {
  hardcodedSecret: {
    // Detects secrets that are directly assigned in source
    // Regex sourced from Semgrep secret scanning rules
    pattern: /\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['"][^'"\n]{8,}['"]/i,
    description: 'Hardcoded secret or credential assignment',
    severity: 'CRITICAL',
    category: patternCategories.AUTH_FAILURES,
    subcategory: '798',
    cwe: '798'
  },

  brokenAuth: {
    // Detects simple password comparisons against constants
    // Regex adapted from Semgrep authentication rules
    pattern: /if\s*\(\s*(?:password|pwd)\s*===?\s*['"][^'"]{1,20}['"]\s*\)/i,
    description: 'Potential weak authentication check',
    severity: 'HIGH',
    category: patternCategories.AUTH_FAILURES,
    subcategory: '287',
    cwe: '287'
  },

  brokenAccessControl: {
    // Detects client-side only admin checks
    pattern: /if\s*\(\s*(?:user\.isAdmin|role\s*===?\s*['"]admin['"])\s*\)/i,
    description: 'Potential broken access control (client-side check)',
    severity: 'HIGH',
    category: patternCategories.ACCESS_CONTROL,
    subcategory: '264',
    cwe: '264'
  }
};

export default authenticationPatterns;