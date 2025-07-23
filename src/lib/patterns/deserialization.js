// Insecure Deserialization patterns
// A08:2021 - Software and Data Integrity Failures

import { patternCategories } from './categories.js';

export const deserializationPatterns = {
  insecureDeserialization: {
    // Insecure deserialization routines
    pattern: /\b(?:pickle|cPickle|unpickle|pyYAML|yaml\.load|unserialize|node-serialize)\b\s*\(/i,
    description: 'Unsafe deserialization of data',
    severity: 'MEDIUM',
    category: patternCategories.INTEGRITY_FAILURES,
    subcategory: '502',
    cwe: '502'
  }
};

export default deserializationPatterns;