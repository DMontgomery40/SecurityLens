// Supply Chain Security patterns
// A06:2021 - Vulnerable and Outdated Components

import { patternCategories } from './categories.js';

export const supplyChainPatterns = {
  suspiciousDependency: {
    // Dependencies pulled from external URLs
    pattern: /"(?:dependencies|devDependencies)"\s*:\s*\{[^}]*https?:\/\/[^}]*\}/i,
    description: 'Suspicious dependency (URL-based) in package.json',
    severity: 'MEDIUM',
    category: patternCategories.SUPPLY_CHAIN,
    subcategory: '1104',
    cwe: '1104'
  }
};

export default supplyChainPatterns;