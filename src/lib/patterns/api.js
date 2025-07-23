// API Security vulnerability patterns

import { patternCategories } from './categories.js';

export const apiPatterns = {
  missingObjectAuth: {
    // Routes exposing IDs without authorization checks
    pattern: /app\.(?:get|post|put|delete)\(['"][^'"]*:\w+['"],\s*[^,]+,\s*[^)]*\)/i,
    description: 'API endpoint may lack object-level authorization',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '284',
    cwe: '284'
  },

  openRedirect: {
    // User input passed directly into redirect APIs
    pattern: /\b(?:res\.redirect|window\.location\.href)\s*=\s*(?:req\.(?:query|body|params)\.|\$\{|\+)/i,
    description: 'Potential open redirect using user input',
    severity: 'MEDIUM',
    category: patternCategories.SECURITY_MISCONFIG,
    subcategory: '601',
    cwe: '601'
  }
};

export default apiPatterns;