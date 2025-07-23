// Injection-related vulnerability patterns
// A03:2021 - Injection

import { patternCategories } from './categories.js';

export const injectionPatterns = {
  sqlInjection: {
    // Adapted from open source Semgrep rules and Red Canary examples
    // Detects queries that combine SQL keywords with dynamic input
    pattern: /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*\b(?:FROM|INTO|WHERE)\b[^;\n]*(?:\+|\$\{)/i,
    description: 'Possible SQL injection via string concatenation in query',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '89',
    cwe: '89'
  },

  commandInjection: {
    // Detects unsafe OS command execution with untrusted input
    // Based on patterns from Red Canary and Semgrep
    pattern: /\b(exec|execSync|spawn|system|os\.popen|subprocess\.(?:call|run|Popen))\b\s*\([^)]*(?:\+|\$\{)[^)]*\)/i,
    description: 'Possible command injection via dynamic input',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '77',
    cwe: '77'
  },

  xssVulnerability: {
    // Detects dangerous DOM sinks fed by unsanitized input
    // Regex adapted from community Semgrep rules
    pattern: /\b(?:innerHTML|outerHTML|document\.write|\.html\()\s*(?:=|\()\s*[^\n]*?(?:\+|\$\{)/i,
    description: 'Potential XSS via dangerous DOM sink',
    severity: 'HIGH',
    category: patternCategories.INJECTION,
    subcategory: '79',
    cwe: '79'
  },

  noSqlInjection: {
    // Detects NoSQL queries that include unescaped user input
    // Pattern derived from Semgrep community rules
    pattern: /\$where\s*:\s*(?:['"].*['"]|\$\{[^}]+\}|[^,]*\+)/i,
    description: 'Potential NoSQL injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '943',
    cwe: '943'
  },

  xxeVulnerability: {
    // Detects external entity declarations in XML documents
    // Inspired by Red Canary detection logic
    pattern: /<!DOCTYPE\s+(?!html)[^>]*\b(?:SYSTEM|PUBLIC)\b[^>]*['"][^'"]+['"]|<!ENTITY\s+\w+\s+SYSTEM\s+['"][^'"]+['"]/i,
    description: 'Potential XXE (XML External Entity) vulnerability',
    severity: 'MEDIUM',
    category: patternCategories.INJECTION,
    subcategory: '611',
    cwe: '611'
  },

  pathTraversal: {
    // Directory traversal sequences in paths
    pattern: /(?:\.\.[/\\])+[^\s]/,
    description: 'Potential path traversal vulnerability',
    severity: 'HIGH',
    category: patternCategories.INJECTION,
    subcategory: '23',
    cwe: '23'
  }
};

export default injectionPatterns;