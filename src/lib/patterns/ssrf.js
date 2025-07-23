// Server-Side Request Forgery patterns
// A10:2021 - SSRF

import { patternCategories } from './categories.js';

export const ssrfPatterns = {
  ssrf: {
    // Detects user-controlled URLs passed to HTTP clients
    pattern: /\b(?:fetch|axios\.(?:get|post|request)|request|get|post)\s*\([^)]*(?:req\.(?:body|query|params)\.|\$\{|\+)/i,
    description: 'Potential SSRF: user input used in server-side request',
    severity: 'HIGH',
    category: patternCategories.SSRF,
    subcategory: '918',
    cwe: '918'
  }
};

export default ssrfPatterns;