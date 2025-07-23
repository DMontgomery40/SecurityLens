// Insecure Design patterns
// A04:2021 - Insecure Design

import { patternCategories } from './categories.js';

export const designPatterns = {
  insecureDesign: {
    // Detect client-side manipulation of pricing or trust in user-provided business-logic data
    pattern: /(totalPrice|price|amount)\s*=\s*(?:req\.(?:body|query|params)|document\.getElementById|\$\(|this\.state)\b/i,
    description: 'Potential insecure design – trusting client-side price/amount input',
    severity: 'MEDIUM',
    category: patternCategories.INSECURE_DESIGN,
    subcategory: '509',
    cwe: '509'
  }
};

export default designPatterns;